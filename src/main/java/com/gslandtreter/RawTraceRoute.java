/* Copyright 2018 Gustavo Spier Landtreter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.gslandtreter;

import com.savarese.rocksaw.net.RawSocket;
import org.savarese.vserv.tcpip.ICMPEchoPacket;
import org.savarese.vserv.tcpip.ICMPPacket;
import org.savarese.vserv.tcpip.OctetConverter;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import static com.savarese.rocksaw.net.RawSocket.*;

public class RawTraceRoute {

    private int receiveTimeout = 1000;

    private RawSocket socket;
    private ICMPEchoPacket sendPacket, recvPacket;
    private int offset, length, dataOffset;
    private int requestType, replyType;
    private byte[] sendData, recvData, srcAddress;
    private int sequence, identifier;

    private int protocolFamily, protocol;

    private long start;
    private List<InetAddress> hops = new ArrayList<InetAddress>();

    private RawTraceRoute(int id, int protocolFamily, int protocol) throws IOException {
        sequence = 0;
        identifier = id;

        sendPacket = new ICMPEchoPacket(1);
        recvPacket = new ICMPEchoPacket(1);
        sendData = new byte[84];
        recvData = new byte[84];

        sendPacket.setData(sendData);
        recvPacket.setData(recvData);
        sendPacket.setIPHeaderLength(5);
        recvPacket.setIPHeaderLength(5);
        sendPacket.setICMPDataByteLength(56);
        recvPacket.setICMPDataByteLength(56);

        offset = sendPacket.getIPHeaderByteLength();
        dataOffset = offset + sendPacket.getICMPHeaderByteLength();
        length = sendPacket.getICMPPacketByteLength();

        this.protocolFamily = protocolFamily;
        this.protocol = protocol;
    }

    public RawTraceRoute(int id, int recvTimeoutMillis) throws IOException {
        this(id);
        receiveTimeout = recvTimeoutMillis;
    }

    private RawTraceRoute(int id) throws IOException {
        this(id, PF_INET, getProtocolByName("icmp"));

        srcAddress = new byte[4];
        requestType = ICMPPacket.TYPE_ECHO_REQUEST;
        replyType = ICMPPacket.TYPE_ECHO_REPLY;
    }

    private void computeSendChecksum(InetAddress host)
            throws IOException {
        sendPacket.computeICMPChecksum();
    }

    private void open() throws IOException {

        if (socket != null) {
            socket.close();
        }

        socket = new RawSocket();
        socket.open(protocolFamily, protocol);

        try {
            socket.setSendTimeout(receiveTimeout);
            socket.setReceiveTimeout(receiveTimeout);
        } catch (java.net.SocketException se) {
            socket.setUseSelectTimeout(true);
            socket.setSendTimeout(receiveTimeout);
            socket.setReceiveTimeout(receiveTimeout);
        }
    }

    /**
     * Closes the raw socket opened by the constructor.  After calling
     * this method, the object cannot be used.
     */
    private void close() throws IOException {
        socket.close();
        socket = null;
    }

    private void sendEchoRequest(InetAddress host, int ttl) throws IOException {
        sendPacket.setType(requestType);
        sendPacket.setCode(0);
        sendPacket.setIdentifier(identifier);
        sendPacket.setSequenceNumber(sequence++);

        ttl = ttl & 255;

        sendPacket.setTTL(ttl);

        start = System.nanoTime();
        OctetConverter.longToOctets(start, sendData, dataOffset);

        computeSendChecksum(host);

        socket.setTTL(ttl);
        socket.write(host, sendData, offset, length);
    }

    private void receive() throws IOException {
        socket.read(recvData, srcAddress);
    }

    public List<InetAddress> execute (InetAddress address, int ttl) throws IOException {

        hops.clear();

        for (int i = 1; i < ttl; i++) {
            try {
                open();
                sendEchoRequest(address, i);

                int code = receiveEchoReply();

                InetAddress hop = getCurrentHop();
                hops.add(hop);

                if (code == 0) {
                    break;
                }

            } catch (InterruptedIOException | UnknownHostException e) {
                hops.add(null);
            } finally {
                close();
            }
        }

        return hops;
    }

    private int getRecvIdentifier() {
        if (recvPacket.getType() == 11) { // TTL Exceeded
            return (recvData[52] & 255) << 8 | recvData[53] & 255;
        } else return recvPacket.getIdentifier();
    }

    private int getRecvSequence() {
        if (recvPacket.getType() == 11) { // TTL Exceeded
            return (recvData[54] & 255) << 8 | recvData[55] & 255;
        } else return recvPacket.getSequenceNumber();
    }


    private int receiveEchoReply() throws IOException {
        do {
            receive();
            double timeSpent = (System.nanoTime() - start) / 1e6;

            if(timeSpent > receiveTimeout) {
                throw new InterruptedIOException("Receive timeout");
            }

        } while (getRecvIdentifier() != identifier);

        return recvPacket.getType();
    }

    private InetAddress getCurrentHop() throws UnknownHostException {
        return recvPacket.getSourceAsInetAddress();
    }

    /**
     * @return The number of bytes in the data portion of the ICMP ping request
     * packet.
     */
    public int getRequestDataLength() {
        return sendPacket.getICMPDataByteLength();
    }

    /**
     * @return The number of bytes in the entire IP ping request packet.
     */
    public int getRequestPacketLength() {
        return sendPacket.getIPPacketLength();
    }

}
