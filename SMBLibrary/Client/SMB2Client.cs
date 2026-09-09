/* Copyright (C) 2017-2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using SMBLibrary.Client.Authentication;
using SMBLibrary.Client.DFS;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Client
{
    public class SMB2Client : ISMBClient
    {
        public static readonly bool SupportMultiRequests = true;
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort DesiredCredits = 16;
        public static readonly int DefaultResponseTimeoutInMilliseconds = 5000;

        private string m_serverName;
        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket m_clientSocket;
        private ConnectionState m_connectionState;
        private int m_responseTimeoutInMilliseconds;
        private bool m_enableSMB311Support = false;

        private object m_incomingQueueLock = new object();
        private List<SMB2Command> m_incomingQueue = new List<SMB2Command>();
        private EventWaitHandle m_incomingQueueEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private SessionPacket m_sessionResponsePacket;
        private EventWaitHandle m_sessionResponseEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private uint m_messageID = 0;
        private readonly object m_messageIDLock = new object();
        private SMB2Dialect m_dialect;
        private bool m_signingRequired;
        private byte[] m_signingKey;
        private bool m_encryptSessionData;
        private byte[] m_encryptionKey;
        private byte[] m_decryptionKey;
        private uint m_maxTransactSize;
        private uint m_maxReadSize;
        private uint m_maxWriteSize;
        private ulong m_sessionID;
        private byte[] m_securityBlob;
        private byte[] m_sessionKey;
        private byte[] m_preauthIntegrityHashValue; // SMB 3.1.1
        private ushort m_availableCredits = 1;
        private bool m_connectionSupportsMultiCredit = false;
        private IAuthenticationClient m_authenticationClient;
        private HashAlgorithm m_hashAlgorithm = HashAlgorithm.SHA512;
        private CipherAlgorithm m_cipherAlgorithm = CipherAlgorithm.Aes128Ccm;
        private SigningAlgorithm m_signingAlgorithm = SigningAlgorithm.AESCMAC;

        public SMB2Client() : this(DefaultResponseTimeoutInMilliseconds)
        {
        }

        public SMB2Client(int responseTimeoutInMilliseconds) : this(responseTimeoutInMilliseconds, false)
        {
        }

        public SMB2Client(bool enableSMB311Support) : this(DefaultResponseTimeoutInMilliseconds, enableSMB311Support)
        {
        }

        public SMB2Client(int responseTimeoutInMilliseconds, bool enableSMB311Support)
        {
            m_responseTimeoutInMilliseconds = responseTimeoutInMilliseconds;
            m_enableSMB311Support = enableSMB311Support;
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public bool Connect(string serverName, SMBTransportType transport)
        {
            m_serverName = serverName;
            IPAddress[] hostAddresses = Dns.GetHostAddresses(serverName);
            if (hostAddresses.Length == 0)
            {
                throw new Exception(String.Format("Cannot resolve host name {0} to an IP address", serverName));
            }
            IPAddress serverAddress = IPAddressHelper.SelectAddressPreferIPv4(hostAddresses);
            return Connect(serverAddress, transport);
        }

        public bool Connect(IPAddress serverAddress, SMBTransportType transport)
        {
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            return Connect(serverAddress, transport, port);
        }

        protected internal bool Connect(IPAddress serverAddress, SMBTransportType transport, int port)
        {
            if (m_serverName == null)
            {
                m_serverName = serverAddress.ToString();
            }

            m_transport = transport;
            if (!m_isConnected)
            {
                if (!ConnectSocket(serverAddress, port))
                {
                    return false;
                }

                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    SessionRequestPacket sessionRequest = new SessionRequestPacket();
                    sessionRequest.CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServerService);
                    sessionRequest.CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                    TrySendPacket(m_clientSocket, sessionRequest);

                    SessionPacket sessionResponsePacket = WaitForSessionResponsePacket();
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
                        m_clientSocket.Disconnect(false);
                        if (!ConnectSocket(serverAddress, port))
                        {
                            return false;
                        }

                        string serverName = GetNetBiosServerName(serverAddress);
                        if (serverName == null)
                        {
                            return false;
                        }

                        sessionRequest.CalledName = serverName;
                        TrySendPacket(m_clientSocket, sessionRequest);

                        sessionResponsePacket = WaitForSessionResponsePacket();
                        if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        {
                            return false;
                        }
                    }
                }

                bool supportsDialect = NegotiateDialect();
                if (!supportsDialect)
                {
                    m_clientSocket.Close();
                }
                else
                {
                    m_isConnected = true;
                }
            }
            return m_isConnected;
        }

        protected virtual string GetNetBiosServerName(IPAddress serverAddress)
        {
            NameServiceClient nameServiceClient = new NameServiceClient(serverAddress);
            return nameServiceClient.GetServerName();
        }

        private bool ConnectSocket(IPAddress serverAddress, int port)
        {
            m_clientSocket = new Socket(serverAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                m_clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException)
            {
                return false;
            }

            m_connectionState = new ConnectionState(m_clientSocket);
            NBTConnectionReceiveBuffer buffer = m_connectionState.ReceiveBuffer;
            m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), m_connectionState);
            return true;
        }

        public void Disconnect()
        {
            if (m_isConnected)
            {
                lock (m_connectionState.ReceiveBuffer)
                {
                    m_clientSocket.Disconnect(false);
                    m_clientSocket.Close();
                    m_connectionState.ReceiveBuffer.Dispose();
                }
                m_isConnected = false;
                lock (m_messageIDLock)
                {
                    m_messageID = 0;
                }
                m_sessionID = 0;
                m_availableCredits = 1;
                m_connectionSupportsMultiCredit = false;
            }
        }

        private bool NegotiateDialect()
        {
            NegotiateRequest request = new NegotiateRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.Capabilities = Capabilities.Encryption;
            request.ClientGuid = Guid.NewGuid();
            request.ClientStartTime = DateTime.Now;
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);
            request.Dialects.Add(SMB2Dialect.SMB300);
            request.Dialects.Add(SMB2Dialect.SMB302);
            if (m_enableSMB311Support)
            {
                request.Dialects.Add(SMB2Dialect.SMB311);
                request.NegotiateContextList = GetNegotiateContextList();
                m_preauthIntegrityHashValue = new byte[64];
            }

            TrySendCommand(request);
            NegotiateResponse response = WaitForCommand(request.MessageID) as NegotiateResponse;
            if (response != null && response.Header.Status == NTStatus.STATUS_SUCCESS)
            {
                m_dialect = response.DialectRevision;
                if (m_dialect < SMB2Dialect.SMB311)
                {
                    m_signingAlgorithm = SMB2Cryptography.GetDefaultSigningAlgorithm(m_dialect);
                }
                // [MS-SMB2] 3.3.5.7 If Connection.Dialect is "3.1.1" and Session.IsAnonymous and Session.IsGuest
                // are set to FALSE and the request is not signed or not encrypted, then the server MUST disconnect the connection.
                m_signingRequired = (response.SecurityMode & SecurityMode.SigningRequired) > 0 ||
                                    response.DialectRevision == SMB2Dialect.SMB311;
                m_maxTransactSize = Math.Min(response.MaxTransactSize, ClientMaxTransactSize);
                m_maxReadSize = Math.Min(response.MaxReadSize, ClientMaxReadSize);
                m_maxWriteSize = Math.Min(response.MaxWriteSize, ClientMaxWriteSize);
                m_securityBlob = response.SecurityBuffer;
                return true;
            }
            return false;
        }

        public NTStatus Login(string domainName, string userName, string password)
        {
            return Login(domainName, userName, password, AuthenticationMethod.NTLMv2);
        }

        public NTStatus Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod)
        {
            string spn = CreateSpn(m_serverName);
            NTLMAuthenticationClient authenticationClient = new NTLMAuthenticationClient(domainName, userName, password, spn, authenticationMethod);
            return Login(authenticationClient);
        }

        public NTStatus Login(IAuthenticationClient authenticationClient)
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            byte[] negotiateMessage = authenticationClient.InitializeSecurityContext(m_securityBlob);
            if (negotiateMessage == null)
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            SessionSetupRequest request = new SessionSetupRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.SecurityBuffer = negotiateMessage;
            TrySendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            while (response is SessionSetupResponse sessionSetupResponse && response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
            {
                byte[] authenticateMessage = authenticationClient.InitializeSecurityContext(sessionSetupResponse.SecurityBuffer);
                if (authenticateMessage == null)
                {
                    return NTStatus.SEC_E_INVALID_TOKEN;
                }

                m_sessionID = response.Header.SessionID;
                request = new SessionSetupRequest();
                request.SecurityMode = SecurityMode.SigningEnabled;
                request.SecurityBuffer = authenticateMessage;
                TrySendCommand(request);
                response = WaitForCommand(request.MessageID);
            }

            if (response is ErrorResponse)
            {
                return response.Header.Status;
            }
            else if (response is SessionSetupResponse finalSessionSetupResponse)
            {
                m_isLoggedIn = (response.Header.Status == NTStatus.STATUS_SUCCESS);
                if (m_isLoggedIn)
                {
                    m_sessionID = response.Header.SessionID;
                    if (finalSessionSetupResponse.SecurityBuffer != null && finalSessionSetupResponse.SecurityBuffer.Length > 0)
                    {
                        // Some authentication mechanisms (e.g. Kerberos) embed acceptor-provider
                        // context data (such as an AP-REP subkey) in the final, successful
                        // SESSION_SETUP response. Give the authentication client a chance to
                        // process it before deriving the session key, since it may override
                        // the key negotiated so far.
                        authenticationClient.InitializeSecurityContext(finalSessionSetupResponse.SecurityBuffer);
                    }

                    var baseSessionKey = authenticationClient.GetSessionKey();
                    if (baseSessionKey == null)
                    {
                        // Report this the same way every other login failure on this path is reported (an
                        // NTStatus return, not an exception) - callers such as ConnectAndLoginToDfsTarget only
                        // wrap Connect() in try/catch and expect Login() failures to come back as a status code.
                        // Also leave the client in a well-defined "not logged in" state - otherwise m_isLoggedIn
                        // (already set true above) would stay true with m_signingKey still null, and the next
                        // inbound response would call VerifySignature with a null signing key.
                        m_isLoggedIn = false;
                        return NTStatus.STATUS_LOGON_FAILURE;
                    }

                    m_authenticationClient = authenticationClient;
                    SessionFlags sessionFlags = finalSessionSetupResponse.SessionFlags;
                    if ((sessionFlags & SessionFlags.IsGuest) > 0)
                    {
                        // [MS-SMB2] 3.2.5.3.1 If the SMB2_SESSION_FLAG_IS_GUEST bit is set in the SessionFlags field of the SMB2
                        // SESSION_SETUP Response and if RequireMessageSigning is FALSE, Session.SigningRequired MUST be set to FALSE.
                        m_signingRequired = false;
                    }
                    else
                    {
                        // Signing always uses a 128-bit key ([MS-SMB2] 3.1.4.2 KDF input), regardless of dialect
                        // or the negotiated cipher's key length - unlike the session key used for encryption below.
                        m_signingKey = SMB2Cryptography.GenerateSigningKey(Truncate16(baseSessionKey), m_dialect, m_preauthIntegrityHashValue);
                    }

                    if (m_dialect >= SMB2Dialect.SMB300)
                    {
                        // Only truncate to 128 bits when the negotiated cipher itself is 128-bit; a 256-bit
                        // cipher (SMB 3.1.1 AES-256-GCM/CCM) needs the full-length session key here.
                        m_sessionKey = (SMB2CipherProvider.GetKeyLengthInBits(m_cipherAlgorithm) == 128) ? Truncate16(baseSessionKey) : baseSessionKey;
                        m_encryptSessionData = (sessionFlags & SessionFlags.EncryptData) > 0;
                        m_encryptionKey = SMB2Cryptography.GenerateClientEncryptionKey(m_sessionKey, m_dialect, m_preauthIntegrityHashValue, m_cipherAlgorithm);
                        m_decryptionKey = SMB2Cryptography.GenerateClientDecryptionKey(m_sessionKey, m_dialect, m_preauthIntegrityHashValue, m_cipherAlgorithm);
                    }
                    else
                    {
                        // Pre-3.0 dialects have no cipher negotiation; the session key here is only ever used
                        // for 128-bit-keyed purposes, so it's always truncated.
                        m_sessionKey = Truncate16(baseSessionKey);
                    }
                }
                return response.Header.Status;
            }
            else
            {
                return NTStatus.STATUS_INVALID_SMB;
            }
        }

        public NTStatus Logoff()
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffRequest request = new LogoffRequest();
            TrySendCommand(request);

            SMB2Command response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                m_isLoggedIn = (response.Header.Status != NTStatus.STATUS_SUCCESS);
                return response.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public List<string> ListShares(out NTStatus status)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            ISMBFileStore namedPipeShare = TreeConnect("IPC$", out status);
            if (namedPipeShare == null)
            {
                return null;
            }

            List<string> shares = ServerServiceHelper.ListShares(namedPipeShare, m_serverName, SMBLibrary.Services.ShareType.DiskDrive, out status);
            namedPipeShare.Disconnect();
            return shares;
        }

        public ISMBFileStore TreeConnect(string shareName, out NTStatus status)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            string sharePath = String.Format(@"\\{0}\{1}", m_serverName, shareName);
            TreeConnectRequest request = new TreeConnectRequest();
            request.Path = sharePath;
            TrySendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                status = response.Header.Status;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is TreeConnectResponse treeConnectResponse)
                {
                    bool encryptShareData = (treeConnectResponse.ShareFlags & ShareFlags.EncryptData) > 0;
                    SMB2FileStore fileStore = new SMB2FileStore(this, response.Header.TreeID, m_encryptSessionData || encryptShareData);
                    if ((treeConnectResponse.ShareFlags & ShareFlags.DfsRoot) > 0)
                    {
                        // [MS-DFSC] The share is a DFS namespace root; wrap the file store so that DFS referrals are followed transparently.
                        return new SMB2DfsFileStore(this, m_serverName, shareName, fileStore);
                    }
                    return fileStore;
                }
            }
            else
            {
                status = NTStatus.STATUS_INVALID_SMB;
            }
            return null;
        }

        public NTStatus Echo()
        {
            EchoRequest request = new EchoRequest();
            TrySendCommand(request);
            SMB2Command response = WaitForCommand(request.MessageID);
            if (response != null)
            {
                return response.Header.Status;
            }
            else
            {
                return NTStatus.STATUS_INVALID_SMB;
            }
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            ConnectionState state = (ConnectionState)ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            lock (state.ReceiveBuffer)
            {
                int numberOfBytesReceived = 0;
                try
                {
                    numberOfBytesReceived = clientSocket.EndReceive(ar);
                }
                catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
                {
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                    return;
                }
                catch (ObjectDisposedException)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                    state.ReceiveBuffer.Dispose();
                    return;
                }
                catch (SocketException ex)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                    state.ReceiveBuffer.Dispose();
                    return;
                }

                if (numberOfBytesReceived == 0)
                {
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                }
                else if (clientSocket.Connected)
                {
                    NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
                    buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                    ProcessConnectionBuffer(state);

                    if (clientSocket.Connected)
                    {
                        try
                        {
                            clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
                        }
                        catch (ObjectDisposedException)
                        {
                            m_isConnected = false;
                            Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                            buffer.Dispose();
                        }
                        catch (SocketException ex)
                        {
                            m_isConnected = false;
                            Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                            buffer.Dispose();
                        }
                    }
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    Log("[ProcessConnectionBuffer] Invalid packet");
                    state.ClientSocket.Close();
                    state.ReceiveBuffer.Dispose();
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, state);
                }
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                byte[] messageBytes;
                bool isEncrypted = m_dialect >= SMB2Dialect.SMB300 && SMB2TransformHeader.IsTransformHeader(packet.Trailer, 0);
                if (isEncrypted)
                {
                    // A corrupted/truncated encrypted frame, or a cipher/key mismatch from a race during
                    // renegotiation, throws CryptographicException/ArgumentException here - handle it the same
                    // way the ReadResponseChain failure below is handled (log, close, dispose) instead of
                    // letting it escape the receive callback unhandled.
                    try
                    {
                        SMB2TransformHeader transformHeader = new SMB2TransformHeader(packet.Trailer, 0);
                        byte[] encryptedMessage = ByteReader.ReadBytes(packet.Trailer, SMB2TransformHeader.Length, (int)transformHeader.OriginalMessageSize);
                        messageBytes = SMB2Cryptography.DecryptMessage(m_decryptionKey, transformHeader, encryptedMessage, m_cipherAlgorithm);
                    }
                    catch (Exception ex)
                    {
                        Log("Failed to decrypt SMB2 response: " + ex.Message);
                        state.ClientSocket.Close();
                        m_isConnected = false;
                        state.ReceiveBuffer.Dispose();
                        return;
                    }
                }
                else
                {
                    messageBytes = packet.Trailer;
                }

                // A server reply to a compound (chained) request is itself a chain of SMB2 messages in one frame, linked via Header.NextCommand - same as request.
                // The original code called SMB2Command.ReadResponse() once and only every recovered the FIRST message in the chain, silently discarding ever other chained response.
                // Parse the full chain instead, and apply the same per-message bookkeeping )credit accounting, negotiate capability detection, MessageID/signature validation,
                // and queueing) to each message that the original code applied to the lone message.
                List<SMB2Command> commands;
                try
                {
                    commands = SMB2Command.ReadResponseChain(messageBytes, 0);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB2 response: " + ex.Message);
                    state.ClientSocket.Close();
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                    return;
                }

                if (m_preauthIntegrityHashValue != null && commands.Count > 0)
                {
                    SMB2Command firstCommand = commands[0];
                    if (firstCommand is NegotiateResponse || (firstCommand is SessionSetupResponse sessionSetupResponse && sessionSetupResponse.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED))
                    {
                        // Preauth integrity hashing covers the whole received message, not a sub-range - NegotiateResponse / SessionSetupRsponse
                        // are never chained with other commands in practice, so hashing the entries frame once here matches the original behavior.
                        // Use m_hashAlgorithm (same field the send-path hash update below uses), not a hardcoded
                        // SHA512, so the two hash updates can't diverge if a future dialect ever negotiates a
                        // different pre-auth integrity hash algorithm (MS-SMB2 only defines SHA-512 today).
                        m_preauthIntegrityHashValue = SMB2Cryptography.ComputeHash(m_hashAlgorithm, ByteUtils.Concatenate(m_preauthIntegrityHashValue, messageBytes));
                    }
                }

                // Credit grants and the negotiate capability check apply once per received message, not once per chained command - a compounded reply's cumulative credit grant is
                // carried by the exchange as a whole (the original single command code applied this exactly once, to the only command it ever saw). Summing every chained command's
                // Header.Credits here would make the client believe it holds more credit than the server actually granted, which a real server can treat as a flow-control protocol
                // violation and respond to by dropping the connection. Use the LAST command in the chain, matching how a non-compounded (single-command) frame behaves.
                SMB2Command lastCommand = commands[commands.Count - 1];
                m_availableCredits += lastCommand.Header.Credits;

                if (lastCommand is NegotiateResponse negotiateResponse)
                {
                    if (m_transport == SMBTransportType.DirectTCPTransport)
                    {
                        m_connectionSupportsMultiCredit = (negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0;
                        if (m_connectionSupportsMultiCredit)
                        {
                            // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client SHOULD disconnect the connection.
                            // Note: Windows clients do not enforce the MaxTransactSize value.
                            // We use a value that we have observed to work well with both Microsoft and non-Microsoft servers.
                            // see https://github.com/TalAloni/SMBLibrary/issues/239
                            int serverMaxTransactSize = (int)Math.Max(negotiateResponse.MaxTransactSize, negotiateResponse.MaxReadSize);
                            int maxPacketSize = SessionPacket.HeaderLength + (int)Math.Min(serverMaxTransactSize, ClientMaxTransactSize) + 256;
                            if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                            {
                                state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                            }
                        }
                    }

                    foreach (var negotiateContex in negotiateResponse.NegotiateContextList)
                    {
                        if (negotiateContex is PreAuthIntegrityCapabilities)
                        {
                            m_hashAlgorithm = FirstOrDefault((negotiateContex as PreAuthIntegrityCapabilities).HashAlgorithms, HashAlgorithm.SHA512);
                        }
                        else if (negotiateContex is EncryptionCapabilities)
                        {
                            m_cipherAlgorithm = FirstOrDefault((negotiateContex as EncryptionCapabilities).Ciphers, CipherAlgorithm.Aes128Ccm);
                        }
                        else if (negotiateContex is SigningCapabilities)
                        {
                            m_signingAlgorithm = FirstOrDefault((negotiateContex as SigningCapabilities).Signings, SigningAlgorithm.AESCMAC);
                        }
                    }
                }

                // [MS-SMB2] 3.2.5.1.3 If signature verification fails, the client MUST discard the received
                // message (the whole compound frame, not just the rest of the chain). So verify every
                // chained command's signature first, in one pass, and only enqueue any of them - in a
                // second pass - once the whole frame is known to be valid. Enqueueing each command as its
                // own signature verifies (as a single-pass loop would) delivers a partial, tampered
                // compound reply to callers before the loop ever reaches the corrupted command.
                int commandOffset = 0;
                var commandsToEnqueue = new List<SMB2Command>();
                foreach (SMB2Command command in commands)
                {
                    int commandLength = (command.Header.NextCommand != 0) ? (int)command.Header.NextCommand : (messageBytes.Length - commandOffset);
                    // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request,
                    // and the client MUST NOT attempt to locate the request, but instead process it as follows:
                    // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
                    // Otherwise, the response MUST be discarded as invalid.
                    if (command.Header.MessageID != 0xFFFFFFFFFFFFFFFF || command.Header.Command == SMB2CommandName.OplockBreak)
                    {
                        bool isInterimResponse = ((command.Header.Flags & SMB2PacketHeaderFlags.AsyncCommand) != 0) && command.Header.Status == NTStatus.STATUS_PENDING;
                        bool shouldBeSigned = m_isLoggedIn && m_signingRequired && !isEncrypted && !isInterimResponse;

                        // Each chained message is signed independently over its own segment, so verify against
                        // that segment (commandOffset...commandLength), not the whole frame.
                        if (shouldBeSigned)
                        {
                            byte[] commandBytes = ByteReader.ReadBytes(messageBytes, commandOffset, commandLength);
                            if (!SMB2Cryptography.VerifySignature(commandBytes, m_signingAlgorithm, m_signingKey))
                            {
                                Log("Invalid SMB2 response signature");
                                return;
                            }
                        }

                        commandsToEnqueue.Add(command);
                    }

                    // Must advance regardless of whether the command above was kept or discarded (per
                    // [MS-SMB2] 3.2.5.1.2) - this walks byte offsets in the raw compound frame, not the
                    // list of commands the client chose to process. Skipping it here would desync every
                    // subsequent chained command's offset (and therefore its signature verification).
                    commandOffset += commandLength;
                }

                if (commandsToEnqueue.Count > 0)
                {
                    lock (m_incomingQueueLock)
                    {
                        m_incomingQueue.AddRange(commandsToEnqueue);
                        m_incomingQueueEventHandle.Set();
                    }
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_sessionResponsePacket = packet;
                m_sessionResponseEventHandle.Set();
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
                state.ReceiveBuffer.Dispose();
            }
        }

        public SMB2Command WaitForCommand(ulong messageID)
        {
            return WaitForCommand(messageID, out bool _);
        }

        internal SMB2Command WaitForCommand(ulong messageID, out bool connectionTerminated)
        {
            connectionTerminated = false;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < m_responseTimeoutInMilliseconds && !(connectionTerminated = !m_clientSocket.Connected))
            {
                lock (m_incomingQueueLock)
                {
                    for (int index = 0; index < m_incomingQueue.Count; index++)
                    {
                        SMB2Command command = m_incomingQueue[index];

                        if (command.Header.MessageID == messageID)
                        {
                            m_incomingQueue.RemoveAt(index);
                            if (command.Header.IsAsync && command.Header.Status == NTStatus.STATUS_PENDING)
                            {
                                index--;
                                continue;
                            }
                            return command;
                        }
                    }
                }
                m_incomingQueueEventHandle.WaitOne(100);
            }
            return null;
        }

        internal SessionPacket WaitForSessionResponsePacket()
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < m_responseTimeoutInMilliseconds)
            {
                if (m_sessionResponsePacket != null)
                {
                    SessionPacket result = m_sessionResponsePacket;
                    m_sessionResponsePacket = null;
                    return result;
                }

                m_sessionResponseEventHandle.WaitOne(100);
            }

            return null;
        }

        private void Log(string message)
        {
            System.Diagnostics.Debug.Print(message);
        }

        internal void TrySendCommand(SMB2Command request)
        {
            TrySendCommand(request, m_encryptSessionData);
        }

        internal void TrySendCommand(SMB2Command request, bool encryptData)
        {
            lock (m_messageIDLock)
            {
                request.Header.MessageID = m_messageID;
            }
            TrySendCommands(new List<SMB2Command>(){ request }, encryptData);
        }

        internal void TrySendCommands(List<SMB2Command> requests, bool encryptData, bool increaseMessageId = true)
        {
            if (requests == null || requests.Count == 0)
                return;

            // 1. Validate the ENTIRE batch before mutating any request's headers - a caller that catches
            // the exception below may reuse the same request objects for a retry (see "Request could be
            // reused" elsewhere), so a batch that gets rejected must come back with every request
            // untouched, not partially mutated by whichever earlier requests were processed before the
            // one that failed.
            if (!m_connectionSupportsMultiCredit)
            {
                foreach (var request in requests)
                {
                    if (request.Header.CreditCharge > 1)
                    {
                        throw new Exception("Attempted to read or write more data than allowed for this connection");
                    }
                }
            }

            // uint, not ushort: summing many multi-credit requests' CreditCharge (each up to ushort.MaxValue)
            // in a batch can exceed ushort range - a ushort accumulator would silently wrap, making the
            // credit-availability check below pass incorrectly and under-report what's actually consumed.
            uint totalCreditCharge = 0;
            // 2. Now that validation passed, calculate credit charge and apply header mutations for every command.
            foreach (var request in requests)
            {
                // [MS-SMB2] If the client encrypts the message [..] then the client MUST set the Signature field of the SMB2 header to zero
                var isSigned = m_signingRequired && !encryptData && m_sessionID != 0 &&
                    ((request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeID != 0) ||
                    (m_dialect >= SMB2Dialect.SMB300 && request.CommandName == SMB2CommandName.Logoff));

                request.Header.IsSigned = isSigned;
                request.Header.SessionID = m_sessionID;

                if (!m_connectionSupportsMultiCredit)
                {
                    // [MS-SMB2] 3.2.4.1.5 If [..] Connection.SupportsMultiCredit is FALSE, CreditCharge SHOULD be set to 0.
                    request.Header.CreditCharge = 0;
                    request.Header.Credits = 1;
                    // MessageID allocation when MultiCredit is false is strictly 1 per command
                    totalCreditCharge += 1;
                }
                else
                {
                    // [MS-SMB2] 3.2.4.1.5 If Connection.SupportsMultiCredit is TRUE:
                    if (request.Header.CreditCharge == 0)
                    {
                        // For READ, WRITE, IOCTL, and QUERY_DIRECTORY requests, CreditCharge field in the SMB2 header SHOULD be set to [..] the value computed.
                        // For all other requests, the client MUST set CreditCharge to 1.
                        request.Header.CreditCharge = 1;
                    }
                    totalCreditCharge += request.Header.CreditCharge;
                }
            }

            // 3. Check internal credit window availability for the ENTIRE batch
            if (m_availableCredits < totalCreditCharge)
            {
                throw new Exception($"Not enough credits. Requested: {totalCreditCharge}, Available: {m_availableCredits}");
            }
            // Safe cast: the check above already guarantees totalCreditCharge <= m_availableCredits, and
            // m_availableCredits is a ushort, so totalCreditCharge is within ushort range here.
            m_availableCredits -= (ushort)totalCreditCharge;

            // 4. Request replenishment credits from the server
            // Best practice: Put the credit request on the LAST command of the compound chain
            var lastRequest = requests[requests.Count - 1];
            if (m_availableCredits < DesiredCredits)
            {
                lastRequest.Header.Credits += (ushort)(DesiredCredits - m_availableCredits);
            }

            // 5. Send the payload over the socket
            TrySendCommands(m_clientSocket, requests, encryptData ? m_encryptionKey : null);

            // 6. Correctly advance the global MessageID counter by the total sum of credit charges
            if (increaseMessageId)
            {
                lock (m_messageIDLock)
                {
                    m_messageID += totalCreditCharge;
                }
            }
        }

        /// <remarks>SMB 3.1.1 only</remarks>
        private List<NegotiateContext> GetNegotiateContextList()
        {
            PreAuthIntegrityCapabilities preAuthIntegrityCapabilities = new PreAuthIntegrityCapabilities();
            preAuthIntegrityCapabilities.HashAlgorithms.Add(HashAlgorithm.SHA512);
            // The salt seeds the SMB 3.1.1 pre-auth integrity hash that detects negotiate downgrade/tampering -
            // a predictable (clock-seeded) salt would weaken that protection, so it needs a CSPRNG, not Random.
            preAuthIntegrityCapabilities.Salt = SecureRandom.GetBytes(32);

            EncryptionCapabilities encryptionCapabilities = new EncryptionCapabilities();
            // Listed in order of preference; the server picks the first entry it also supports.
            encryptionCapabilities.Ciphers.Add(CipherAlgorithm.Aes256Gcm);
            encryptionCapabilities.Ciphers.Add(CipherAlgorithm.Aes128Gcm);
            encryptionCapabilities.Ciphers.Add(CipherAlgorithm.Aes256Ccm);
            encryptionCapabilities.Ciphers.Add(CipherAlgorithm.Aes128Ccm);

            SigningCapabilities signingCapabilities = new SigningCapabilities();
            // Listed in order of preference; the server picks the first entry it also supports.
            signingCapabilities.Signings.Add(SigningAlgorithm.AESGMAC);
            signingCapabilities.Signings.Add(SigningAlgorithm.AESCMAC);
            signingCapabilities.Signings.Add(SigningAlgorithm.HMACSHA256);

            return new List<NegotiateContext>()
            {
                preAuthIntegrityCapabilities,
                encryptionCapabilities,
                signingCapabilities
            };
        }

        public uint MaxTransactSize
        {
            get
            {
                return m_maxTransactSize;
            }
        }

        public uint MaxReadSize
        {
            get
            {
                return m_maxReadSize;
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                return m_maxWriteSize;
            }
        }

        public SMBTransportType Transport
        {
            get
            {
                return m_transport;
            }
        }

        public bool IsConnected
        {
            get
            {
                return m_isConnected;
            }
        }

        public ushort AvailableCredits
        {
            get
            {
                return m_availableCredits;
            }
        }

        public uint GetNextMessageId()
        {
            lock (m_messageIDLock)
            {
                return m_messageID++;
            }
        }

        private void TrySendCommands(Socket socket, List<SMB2Command> requests, byte[] encryptionKey)
        {
            SessionMessagePacket packet = new SessionMessagePacket();
            if (encryptionKey != null)
            {
                byte[] requestBytes = SMB2Command.GetCommandChainBytes(requests, null, m_signingAlgorithm);
                packet.Trailer = SMB2Cryptography.TransformMessage(encryptionKey, requestBytes, m_sessionID, m_cipherAlgorithm);
            }
            else
            {
                packet.Trailer = SMB2Command.GetCommandChainBytes(requests, m_signingKey, m_signingAlgorithm);
                if (requests.Count == 1 && m_preauthIntegrityHashValue != null && (requests[0] is NegotiateRequest || requests[0] is SessionSetupRequest))
                {
                    m_preauthIntegrityHashValue = SMB2Cryptography.ComputeHash(
                        m_hashAlgorithm, ByteUtils.Concatenate(m_preauthIntegrityHashValue, packet.Trailer));
                }
            }
            TrySendPacket(socket, packet);
        }

        private void TrySendPacket(Socket socket, SessionPacket packet)
        {
            try
            {
                byte[] packetBytes = packet.GetBytes();
                socket.Send(packetBytes);
            }
            catch (SocketException)
            {
                m_isConnected = false;
            }
            catch (ObjectDisposedException)
            {
                m_isConnected = false;
            }
        }

        private static string CreateSpn(string serverAddress)
        {
            return $"cifs/{serverAddress}";
        }

        // Enumerable .FirstOrDefault() is a .NET 6+ only available, but this project also
        // targets net20/net40/netstandard2.0 (Platform=Net) where it doen't exist - use this instead.
        private static T FirstOrDefault<T>(IEnumerable<T> source, T defaultValue)
        {
            foreach (T item in source)
            {
                return item;
            }
            return defaultValue;
        }

        // Copies (or zero-pads) the input array to a new 16-byte array. Used wherever a key derivation input must be
        // exactly 128 bits regardless of the actual session key length (e.g. Kerberos AES256's 32-byte key).
        private static byte[] Truncate16(byte[] input)
        {
            byte[] truncated = new byte[16];
            Array.Copy(input, truncated, Math.Min(input.Length, 16));
            return truncated;
        }

        /// <summary>
        /// Connects to a DFS referral target server and logs in by reusing this client's authentication client,
        /// rebinding its security context to the target server (see IAuthenticationClient.ResetSecurityContext).
        /// </summary>
        internal SMB2Client ConnectAndLoginToDfsTarget(string serverName)
        {
            if (m_authenticationClient == null)
            {
                return null;
            }

            SMB2Client targetClient = new SMB2Client(m_responseTimeoutInMilliseconds, m_enableSMB311Support);
            try
            {
                if (!targetClient.Connect(serverName, m_transport))
                {
                    return null;
                }
            }
            catch
            {
                // Connect throws when the server name cannot be resolved
                return null;
            }

            m_authenticationClient.ResetSecurityContext(CreateSpn(serverName));
            NTStatus loginStatus = targetClient.Login(m_authenticationClient);
            if (loginStatus != NTStatus.STATUS_SUCCESS)
            {
                targetClient.Disconnect();
                return null;
            }

            return targetClient;
        }
    }
}
