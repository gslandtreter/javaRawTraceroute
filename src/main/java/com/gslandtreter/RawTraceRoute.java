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
import java.util.concurrent.ThreadLocalRandom;

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

    private RawTraceRoute(int id, int protocolFamily, int protocol)
            throws IOException {
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

    private RawTraceRoute(int id, int recvTimeoutMillis) throws IOException {
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

    private List<InetAddress> execute(InetAddress address, int ttl) throws IOException {

        hops.clear();

        for (int i = 1; i < ttl; i++) {
            open();
            sendEchoRequest(address, i);

            try {
                int code = receiveEchoReply();

                InetAddress hop = getCurrentHop();
                hops.add(hop);

                if (code == 0) {
                    break;
                }

            } catch (InterruptedIOException e) {
                hops.add(null);
            } catch (UnknownHostException e) {
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
    private int getRequestDataLength() {
        return sendPacket.getICMPDataByteLength();
    }

    /**
     * @return The number of bytes in the entire IP ping request packet.
     */
    private int getRequestPacketLength() {
        return sendPacket.getIPPacketLength();
    }

    public static final void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) {
            System.err.println("usage: Ping host [count]");
            System.exit(1);
        }

        try {
            final InetAddress address = InetAddress.getByName(args[0]);
            final String hostname = address.getCanonicalHostName();
            final String hostaddr = address.getHostAddress();
            final int maxHops;
            // Ping programs usually use the process ID for the identifier,
            // but we can't get it and this is only a demo.
            final int id = ThreadLocalRandom.current().nextInt(1, 65535);
            final RawTraceRoute traceRoute;

            if (args.length == 2)
                maxHops = Integer.parseInt(args[1]);
            else
                maxHops = 5;

            traceRoute = new RawTraceRoute(id);

            System.out.println("PING " + hostname + " (" + hostaddr + ") " +
                    traceRoute.getRequestDataLength() + "(" +
                    traceRoute.getRequestPacketLength() + ") bytes of data).");

            List<InetAddress> hops = traceRoute.execute(address, maxHops);
            System.out.println(hops.toString());

        } catch (Exception e) {

            e.printStackTrace();
        }
    }

}
