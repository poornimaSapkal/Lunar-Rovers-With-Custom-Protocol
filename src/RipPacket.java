import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

/**
 * This is a class which represents a RipPacket. It an array list of router table entries to store routing information
 * for that particular rover.
 *
 * @author Poornima Sapkal
 */

public class RipPacket {
    public ArrayList<RouterTableEntry> routerTable;
    public byte command;
    public byte version;
    public byte id;
    public byte unused;

    /**
     * The RipPacket constructor sets the command, version, id, unused bytes and routerTable for the rover that's
     * creating the RipPacket.
     *
     * @param id roverId
     * @param routingTable rover's routing table
     */
    public RipPacket(int id, ArrayList<RouterTableEntry> routingTable) {
        this.command = (byte) 1;
        this.version = (byte) 2;
        //the first byte of the unused bytes is used to store the rover id
        this.id = (byte) id;
        this.unused = (byte) 0;
        this.routerTable = routingTable;
    }

    /**
     *
     */

    public RipPacket() {
        this.routerTable = new ArrayList<RouterTableEntry>();
    }

    /**
     * This function returns the bytes that are contained in the RipPacket.
     *
     * @return bytes that are contained in the RipPacket
     * @throws UnknownHostException
     */

    public byte[] getMyBytes() throws UnknownHostException {
        ArrayList<Byte> bytesToSend = new ArrayList<>();

        bytesToSend.add(this.command);
        bytesToSend.add(this.version);
        bytesToSend.add(this.id);
        bytesToSend.add(this.unused);


        for (int i = 0; i < routerTable.size(); i++) {
            RouterTableEntry entry = routerTable.get(i);

            bytesToSend.add(entry.addressFamilyIdentifier[0]);
            bytesToSend.add(entry.addressFamilyIdentifier[1]);
            bytesToSend.add(entry.routeTag[0]);
            bytesToSend.add(entry.routeTag[1]);


            String roverIpAddress = entry.ipAddress;
            InetAddress iNetAddr = InetAddress.getByName(roverIpAddress);

            byte[] ipBytes = iNetAddr.getAddress();
            bytesToSend.add(ipBytes[0]);
            bytesToSend.add(ipBytes[1]);
            bytesToSend.add(ipBytes[2]);
            bytesToSend.add(ipBytes[3]);


            bytesToSend.add(entry.subnetMask[0]);
            bytesToSend.add(entry.subnetMask[1]);
            bytesToSend.add(entry.subnetMask[2]);
            bytesToSend.add(entry.subnetMask[3]);

            String nextHopAddress = entry.nextHop;
            InetAddress iNetAddrNextHop = InetAddress.getByName(nextHopAddress);

            byte[] ipBytesNextHop = iNetAddrNextHop.getAddress();
            bytesToSend.add(ipBytesNextHop[0]);
            bytesToSend.add(ipBytesNextHop[1]);
            bytesToSend.add(ipBytesNextHop[2]);
            bytesToSend.add(ipBytesNextHop[3]);

            bytesToSend.add(entry.metric[0]);
            bytesToSend.add(entry.metric[1]);
            bytesToSend.add(entry.metric[2]);
            bytesToSend.add(entry.metric[3]);

        }
        byte[] byteArrayToSend = new byte[bytesToSend.size()];
        for (int i = 0; i < bytesToSend.size(); i++) {
            byteArrayToSend[i] = bytesToSend.get(i);
        }
        return byteArrayToSend;
    }

    /**
     * The decodeRipPacket function takes in the bytes of the received packet and creates a rip packet representation
     * of those bytes.
     *
     * @param incomingBytes RipPacket bytes
     * @param packetLength length of the received packet
     * @throws UnknownHostException
     */

    public void decodeRipPacket(byte[] incomingBytes, int packetLength) throws UnknownHostException {
        this.command = incomingBytes[0];
        this.version = incomingBytes[1];
        this.id = incomingBytes[2];
        this.unused = incomingBytes[3];

        int byteCount = 4;

        while (packetLength > byteCount) {
            RouterTableEntry entry = new RouterTableEntry();

            entry.addressFamilyIdentifier[0] = incomingBytes[byteCount];
            byteCount++;
            entry.addressFamilyIdentifier[1] = incomingBytes[byteCount];
            byteCount++;

            entry.routeTag[0] = incomingBytes[byteCount];
            byteCount++;
            entry.routeTag[1] = incomingBytes[byteCount];
            byteCount++;

            //IP Address

            byte[] ipBytes = new byte[4];

            ipBytes[0] = incomingBytes[byteCount];
            byteCount++;
            ipBytes[1] = incomingBytes[byteCount];
            byteCount++;
            ipBytes[2] = incomingBytes[byteCount];
            byteCount++;
            ipBytes[3] = incomingBytes[byteCount];
            byteCount++;

            entry.ipAddress = InetAddress.getByAddress(ipBytes).getHostAddress();

            entry.subnetMask[0] = incomingBytes[byteCount];
            byteCount++;
            entry.subnetMask[1] = incomingBytes[byteCount];
            byteCount++;
            entry.subnetMask[2] = incomingBytes[byteCount];
            byteCount++;
            entry.subnetMask[3] = incomingBytes[byteCount];
            byteCount++;


            //Next Hop

            byte[] nextHopBytes = new byte[4];

            nextHopBytes[0] = incomingBytes[byteCount];
            byteCount++;
            nextHopBytes[1] = incomingBytes[byteCount];
            byteCount++;
            nextHopBytes[2] = incomingBytes[byteCount];
            byteCount++;
            nextHopBytes[3] = incomingBytes[byteCount];
            byteCount++;

            entry.nextHop = InetAddress.getByAddress(nextHopBytes).getHostAddress();

            entry.metric[0] = incomingBytes[byteCount];
            byteCount++;
            entry.metric[1] = incomingBytes[byteCount];
            byteCount++;
            entry.metric[2] = incomingBytes[byteCount];
            byteCount++;
            entry.metric[3] = incomingBytes[byteCount];
            byteCount++;

            this.routerTable.add(entry);
        }
    }
}
