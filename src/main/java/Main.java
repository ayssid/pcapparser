import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;



import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

public class Main {
    static final String HEXES = "0123456789ABCDEF";


    public static void main(String[] args) throws IOException {

        final Pcap pcap = Pcap.openStream("C:\\category62\\rekam-1.pcap");

        pcap.loop(new PacketHandler() {
            @Override
            public boolean nextPacket(Packet packet) throws IOException {
                DatagramSocket socket;
                InetAddress group;
                socket = new DatagramSocket();

                group = InetAddress.getByName("224.0.0.3");

                DatagramPacket packet1;

               /* if (packet.hasProtocol(Protocol.TCP)) {

                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    Buffer buffer = tcpPacket.getPayload();
                    if (buffer != null) {
                        System.out.println("TCP: " + buffer);
                    }
                } else */
                if (packet.hasProtocol(Protocol.UDP)) {

                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                    Buffer buffer = udpPacket.getPayload();
                    byte[] data = new byte[1024];
                    buffer.getByes(data);

                    if(data[0] == 0x3e) {
                        packet1 = new DatagramPacket(data, data.length, group, 8888);
                        socket.send(packet1);
                        System.out.println("UDP: " + getHex(data));
                        socket.close();
                        try {
                            TimeUnit.SECONDS.sleep(1);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }

                }
                return true;
            }
        });
    }

    public static String getHex( byte [] raw ) {
        if ( raw == null ) {
            return null;
        }
        final StringBuilder hex = new StringBuilder( 2 * raw.length );
        for ( final byte b : raw ) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4))
                    .append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }
}
