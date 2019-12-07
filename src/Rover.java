import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.net.*;

/**
 * This is a class which represents a Rover. It can receive and send RIP packets to other rovers on the same network.
 * It uses multicast to send its routing information to the other rovers. It implements distance vector routing
 * algorithm to find cheapest routes.
 *
 * @author Poornima Sapkal
 */

public class Rover extends Thread {

    private int roverId;
    private ArrayList<RouterTableEntry> routerTable = new ArrayList<RouterTableEntry>();
    private HashMap<String, Timer> timerMap = new HashMap<>();
    private int ROUTER_UNREACHABLE_COST = 16;
    private static int ripPort;

    private Rover(int id) {
        this.roverId = id;
    }

    //for sending the files (BaseStation)
    private static FileInputStream fin;
    private static DatagramSocket socket;
    private static DatagramSocket receiveSocket;
    private static HashMap<Integer, Timer> retransmissionTimer = new HashMap<>();
    private static HashMap<Integer, Integer> fragmentAcknowledgement = new HashMap<>();
    private int fragmentNumber;
    private int numFragments;
    private int mostRecentlySentPacket = 0;
    private volatile int ackdPacket = 0;
    private static byte[] bytesToSend = new byte[5000];
    private static byte[] totalNumberOfFragments;
    private static byte[] fragmentNumberBeingSent;
    private static String destinationIpAddress;
    int count; // Number of fragments that have been sent successfully to the receiver

    //for receiving the file (Rover)
    static ArrayList<byte[]> packets = new ArrayList<>();
    public static Set<Integer> packetsAdded = new HashSet<>();
    public static String fileToCreate;

    /**
     * The sendUpdates function sends creates a rip packet and sends that packet to all the rovers
     * that are connected to it on that network.
     *
     * @throws IOException
     */

    private void sendUpdates() throws IOException {
        InetAddress group = InetAddress.getByName("224.0.0.252");
        MulticastSocket multicastSocket = new MulticastSocket(ripPort);
        RipPacket rp = new RipPacket(roverId, this.routerTable);

        byte[] ripPacket = rp.getMyBytes();
        System.out.println("\n\n");
        DatagramPacket packet = new DatagramPacket(ripPacket, ripPacket.length, group, 3456);
        multicastSocket.send(packet);
        multicastSocket.close();
    }

    /**
     * The send function calls the sendUpdates function after every 5 seconds.
     */

    private void send() {
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                try {
                    sendUpdates();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }, 2000, 5000);
    }

    public String getPrivateIP(int roverId){
        String privateIp = "10.0.0."+roverId;
        return privateIp;
    }

    public String getPublicIP(){
        InetAddress localhost = null;
        try {
            localhost = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        String publicIp  = localhost.getHostAddress().trim();
        return publicIp;
    }


    /**
     * The markRoversAsUnreachable function is called when the rovers stop responding. This function
     * scans the rover's routing table and updates the cost to INF (16) if a particular rover is
     * no longer connected to this rover.
     *
     * @param ipAddress IPAddress of the rover that has gone down
     */

    private void markRoversAsUnreachable(String ipAddress, String privateIp) {
        for (int i = 0; i < routerTable.size(); i++) {
            //can use the entryPresentInRT table function
            RouterTableEntry entry = routerTable.get(i);
            if (entry.ipAddress.equals(privateIp) || entry.nextHop.equals(ipAddress)) {
                System.out.println("Unreachable");
                entry.metric[3] = (byte) ROUTER_UNREACHABLE_COST;
            }

        }
    }

    /**
     * The receive function is continuously listening for incoming packets. It adds entries to its routing
     * table if it doesn't have information about a particular rover and it prints out the routing table
     * information. It also creates a timer for every rover that communicates with it. The timerMap stores
     * a mapping of the IPAddress to the timer for every rover that it communicates with.
     * <p>
     * The timer expires after 10 seconds. If the rover hasn't heard from another rover in over 10 seconds,
     * the rover is marked as unreachable.
     *
     * @throws IOException
     */

    private void receive() throws IOException {
        InetAddress group = InetAddress.getByName("224.0.0.252");
        MulticastSocket multicastSocket = new MulticastSocket(3456);
        multicastSocket.joinGroup(group);

        while (true) {
            byte[] buff = new byte[512];
            DatagramPacket packet = new DatagramPacket(buff, buff.length);
            multicastSocket.receive(packet);
            if ((int) buff[2] == roverId) {
                continue;
            }
            System.out.println("IP Address of packet that sent:"+packet.getAddress().toString().substring(1));

            String senderIp = packet.getAddress().toString().substring(1);

            RipPacket rp = new RipPacket();
            rp.decodeRipPacket(buff, packet.getLength());
            addFirstEntryToRoutingTable(rp, senderIp);
            addRoutingTableEntries(rp, senderIp);

            String ipAddr = senderIp;
            String privateIp = getPrivateIP(rp.id);
            Timer timer = new Timer();

            if (timerMap.containsKey(ipAddr)) {
                timerMap.get(ipAddr).cancel();
                timerMap.remove(ipAddr);
                timerMap.put(ipAddr, timer);
            } else {
                timerMap.put(ipAddr, timer);
            }

            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    markRoversAsUnreachable(ipAddr, privateIp);
                }
            }, 10000);

            printRoutingTable();


        }
    }

    /**
     * This function is called every time a rover receives a RIP packet. It adds the rover's information or
     * updates the information depending on whether the rover's information is already present or not.
     *
     * @param rp RipPacket that the rover has received.
     */

    private void addFirstEntryToRoutingTable(RipPacket rp, String senderIp) {
        boolean contains = false;
        // String incomingIpAddress = "172.18." + rp.id + ".1";
        String incomingIpAddress = getPrivateIP(rp.id);
        int cost = 1;
        //checking if my router table contains the incoming ip address entry
        for (int i = 0; i < routerTable.size(); i++) {
            RouterTableEntry entry = routerTable.get(i);
            if (entry.ipAddress.equals(incomingIpAddress)) {
                contains = true;
                entry.metric[3] = 1;
                entry.nextHop = senderIp;
            }

        }
        RouterTableEntry entry = new RouterTableEntry();
        //add incoming entry in the router table if it's not present
        if (!contains) {

            byte[] addressFamilyIdentifier = new byte[2]; // 2 bytes
            //addressFamilyIdentifier[0] = (byte) 0;
            //addressFamilyIdentifier[1] = (byte) 0;

            byte[] routeTag = new byte[2]; // 2 bytes
            routeTag[0] = (byte) 3;
            routeTag[1] = (byte) 9;

            String ipAddress = "172.18." + rp.id + ".1";

            byte[] subnetMask = new byte[4]; // 4 bytes
            subnetMask[0] = (byte) 0;
            subnetMask[1] = (byte) 0;
            subnetMask[2] = (byte) 0;
            subnetMask[3] = (byte) 0;

            String nextHop = "172.18." + rp.id + ".1";

            byte[] metric = new byte[4]; // 4 bytes
            metric[0] = (byte) 0;
            metric[1] = (byte) 0;
            metric[2] = (byte) 0;
            metric[3] = (byte) cost;

            entry.addressFamilyIdentifier = addressFamilyIdentifier;
            entry.routeTag = routeTag;
            entry.ipAddress = incomingIpAddress;
            entry.subnetMask = subnetMask;
            entry.nextHop = senderIp;
            entry.metric = metric;
            routerTable.add(entry);
        }

    }

    /**
     * The addRoutingTableEntries function adds the routing table entries that are present in the RIP packet.
     * It implements the distance vector routing algorithm to decide the best route and updates the rover's
     * routing table.
     *
     * @param rp RipPacket that the rover has received.
     */

    private void addRoutingTableEntries(RipPacket rp, String senderIp) {
        //checking if my router table contains the incoming ip address entry
        String roverIp = getPublicIP();
        for (int i = 0; i < rp.routerTable.size(); i++) {
            RouterTableEntry senderEntry = rp.routerTable.get(i);
            RouterTableEntry myEntry = entryPresentInRT(senderEntry);
            if (myEntry != null) {
                // entry is present in the receiver's routing table
                // split horizon
                if (roverIp.equals(senderEntry.nextHop)) {
                    continue;
                }

                if (myEntry.nextHop.equals(senderIp)) {
                    myEntry.metric[3] = (byte) ((int) senderEntry.metric[3] + 1);
                }
                // compute new cost
                int newCost = (int) senderEntry.metric[3] + 1;
                if (newCost < (int)myEntry.metric[3]) {
                    // new cost is lesser than existing cost
                    System.out.println("Updating");
                    myEntry.metric[3] = (byte) newCost;
                    myEntry.nextHop = senderIp;

                }

                if ((int) myEntry.metric[3] >= 16) {
                    myEntry.metric[3] = (byte) ROUTER_UNREACHABLE_COST;
                }

            } else  {
                // entry is not present in the receiver's routing table and
                // enrty's ip is not the receiver's ip address
                senderEntry.metric[3] = (byte) ((int) senderEntry.metric[3] + 1);
                senderEntry.nextHop = senderIp;
                if (senderEntry.metric[3] >= 16) {
                    senderEntry.metric[3] = (byte) ROUTER_UNREACHABLE_COST;
                }

                if(!senderEntry.ipAddress.equals(getPrivateIP(roverId))){
                    routerTable.add(senderEntry);
                }

            }

        }
    }

    /**
     * This function prints the entries that are in the routing table.
     */

    public void printRoutingTable(){
        System.out.println("\nThis is Rover " + roverId + "'s routing table:");
        System.out.println("\n=========================================================================");
        System.out.println("\t IP Address \t\tNext Hop\t\tMetric");
        System.out.println("=========================================================================");

        for (int i = 0; i < routerTable.size(); i++) {
            RouterTableEntry entry = routerTable.get(i);
            String ipAddress = entry.ipAddress;
            String nextHop = entry.nextHop;
            int metric = (int) entry.metric[3];
            System.out.println("\t" + ipAddress + "/24" +  "\t\t" + nextHop + "\t\t" + metric);
        }
    }

    /**
     * The entryPresentInRT function checks if an entry is present in the routing table or not. If it's present,
     * it returns that entry else it returns null.
     *
     * @param senderEntry entry from the RIP packet.
     * @return receiverEntry if found else null.
     */

    private RouterTableEntry entryPresentInRT(RouterTableEntry senderEntry) {
        //go through my routing table for that entry
        for (int i = 0; i < routerTable.size(); i++) {
            RouterTableEntry receiverEntry = routerTable.get(i);
            if (receiverEntry.ipAddress.equals(senderEntry.ipAddress)) {
                return receiverEntry;
            }
        }
        return null;
    }

    /**
     * The main function creates a rover and assigns it an ID which is specified in the command line arguments.
     * It creates a thread which calls the receive function and keeps listening for incoming RIP packets. It also
     * calls the send function which sends its routing information to other rovers on the network.
     *
     * @param args Rover ID
     */

    //For sending the file (BaseStation)

    /**
     * The readBytesFromFile function reads a specified number of bytes from the file.
     *
     * @param numberOfBytesToRead number of bytes that are to be read
     * @return byte array containing the bytes read
     * @throws IOException
     */

    private static byte[] readBytesFromFile(int numberOfBytesToRead) throws IOException {
        if (numberOfBytesToRead > (fin.available())){
            numberOfBytesToRead = fin.available();
        }
        byte[] bytes = new byte[numberOfBytesToRead];
        for (int i = 0; i < numberOfBytesToRead; i++) {
            try {
                bytes[i] = (byte) fin.read();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return bytes;
    }

    /**
     * The resendBytesFromFile will resend the bytes for which an acknowledgement has not been received. It will not read
     * new bytes from the file but rather send the previous bytes that were read.
     *
     * @param bytesToSend bytes for which an ack was not received
     * @param fragmentNumber fragment number which is being sent
     * @param numFragments total number of fragments
     * @throws IOException
     */

    private void resendBytesFromFile(byte[] bytesToSend, byte[] fragmentNumber, byte[] numFragments, String ipAddress) throws IOException {
        if (fragmentAcknowledgement.get(fragmentNumber) != 1) {

            System.out.println("Retransmission of Bytes..");

            //source IP Address
            String sourceAddress = getPrivateIP(roverId);
            InetAddress sourceInetAddress = InetAddress.getByName(sourceAddress);
            byte[] sourceIpBytes = sourceInetAddress.getAddress();

            //destination IP Address
            InetAddress destInetAddress = InetAddress.getByName(destinationIpAddress);
            byte[] destIpBytes = destInetAddress.getAddress();

            InetAddress ip = InetAddress.getByName(ipAddress);
            CustomPacket customPacket = new CustomPacket(sourceIpBytes, destIpBytes, numFragments,fragmentNumber, bytesToSend);
            customPacket.setAck(0);
            byte[] customPacketBytes = customPacket.getBytes();
            DatagramPacket packet = new DatagramPacket(customPacketBytes, customPacketBytes.length, ip, 4234);
            socket.send(packet);

            ByteBuffer fragmentNumberBuffer = ByteBuffer.wrap(fragmentNumber);
            fragmentNumberBuffer.order(ByteOrder.BIG_ENDIAN);
            mostRecentlySentPacket = fragmentNumberBuffer.getInt();
        }
    }


    /**
     * The sendBytes function reads in a specified number of bytes from the file and sends those bytes to the receiver.
     *
     * @param fileName name of the file that is to be sent
     * @throws IOException
     */

    public void sendBytesToRover(String fileName, String ipAddress) throws IOException {
        count = 0; // Number of fragments that have been sent to the receiver
        fragmentNumber = 0;

        File file = new File(fileName);
        fin = new FileInputStream(file);
        int fileSize = fin.available(); // Size of the file that is to be sent

        // Fixed size of one fragment
        int oneFragmentSize = 5000;
        numFragments = (int) Math.ceil(fileSize / oneFragmentSize) + 1; // Number of fragments required to send the file
        System.out.println("Sending.."+numFragments+" Fragments");

        InetAddress ip = InetAddress.getByName(ipAddress);

        //source IP Address
        String sourceAddress = getPrivateIP(roverId);
        InetAddress sourceInetAddress = InetAddress.getByName(sourceAddress);
        byte[] sourceIpBytes = sourceInetAddress.getAddress();

        //destination IP Address
        InetAddress destInetAddress = InetAddress.getByName(destinationIpAddress);
        byte[] destIpBytes = destInetAddress.getAddress();


        while (count < numFragments) {
            if (mostRecentlySentPacket == ackdPacket) {
                bytesToSend = readBytesFromFile(oneFragmentSize);
                fragmentNumber++;
                mostRecentlySentPacket = fragmentNumber;
                totalNumberOfFragments = ByteBuffer.allocate(4).putInt(numFragments).array();
                fragmentNumberBeingSent = ByteBuffer.allocate(4).putInt(fragmentNumber).array();



                CustomPacket customPacket = new CustomPacket(sourceIpBytes, destIpBytes, totalNumberOfFragments, fragmentNumberBeingSent, bytesToSend);
                customPacket.setAck(0);
                byte[] customPacketBytes = customPacket.getBytes();
                DatagramPacket packet = new DatagramPacket(customPacketBytes, customPacketBytes.length, ip, 4234);
                fragmentAcknowledgement.put(fragmentNumber, 0);
                Timer timer = new Timer();
                timer.schedule(new TimerTask() {
                    @Override
                    public void run() {
                        try {
                            resendBytesFromFile(bytesToSend, fragmentNumberBeingSent, totalNumberOfFragments, ipAddress);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }, 7000);
                retransmissionTimer.put(fragmentNumber, timer);
                System.out.println("Sending Fragment "+fragmentNumber);
                socket.send(packet);
                count++;
            }
        }

        byte[] finPayload = new byte[1];
        finPayload[0] = (byte)0;
        CustomPacket finPacket = new CustomPacket(sourceIpBytes, destIpBytes, totalNumberOfFragments, fragmentNumberBeingSent, finPayload);
        finPacket.setFin(1);
        byte[] finPacketBytes = finPacket.getBytes();
        DatagramPacket finDatagram = new DatagramPacket(finPacketBytes, finPacketBytes.length, ip, 4234);
        socket.send(finDatagram);


    }


    /**
     * This function listens in for acknowledgements that are sent from the receiver. It updates the value of ackdPacket
     * which keeps track of the most recently acknowledged fragment. On receiving an ack for a particular fragment, it
     * updates the ack for that fragment in the fragmentAcknowledgement hashmap. It also cancels the retransmissionTimer
     *
     * @throws IOException
     */



    public void listenForAcknowledgements() throws IOException {

        receiveSocket = new DatagramSocket(8432); // socket on which the acknowledgements will be received
        while (count < numFragments + 1) {
            byte[] receive = new byte[6000];
            DatagramPacket receivedAckPacket = new DatagramPacket(receive, receive.length);
            receiveSocket.receive(receivedAckPacket);

            // Decoding received packet
            CustomPacket pkt = new CustomPacket(receive, receivedAckPacket.getLength());
            ByteBuffer fragmentNumberByteBuffer = ByteBuffer.wrap(pkt.fragmentNumber);
            fragmentNumberByteBuffer.order(ByteOrder.BIG_ENDIAN);
            ackdPacket = fragmentNumberByteBuffer.getInt();
            fragmentAcknowledgement.put(ackdPacket, 1);

            System.out.println("Received ACK for Packet Fragment " + ackdPacket);
            if (retransmissionTimer.containsKey(ackdPacket)) {
                System.out.println("Cancel Retransmission for " + ackdPacket);
                retransmissionTimer.get(ackdPacket).cancel();
                retransmissionTimer.remove(ackdPacket);
            }
            System.out.println("Packet Flags:"+pkt.flags);

            if((pkt.flags==3)){
                System.out.println("Received The FIN ACK");
                System.out.println("Closing socket");
                socket.close();
                break;
            }
        }

    }

    // For receiving the file (Rover)

    /**
     * The writeBytesToFile function writes the packets that it receiveFiled which are present in the packets array list to
     * the file.
     *
     * @throws IOException
     */
    public static void writeBytesToFile() throws IOException {
        try (FileOutputStream fileOuputStream = new FileOutputStream(fileToCreate)) {
            for (int i = 0; i < packets.size(); i++) {
                fileOuputStream.write(packets.get(i));
            }
        }
    }



    /**
     * The receiveFile function listens for incoming packets and adds the dataPayload of the receiveFiled packets to an
     * ArrayList of packets. When all the fragments have been receiveFiled, it writes the packets from the
     * packets arraylist to the file.
     *
     * @throws IOException
     */

    public static void receiveFile() throws IOException {
        // Receiving
        System.out.println("Receiving..");

        DatagramSocket socket = new DatagramSocket(4234);
        int receiveFileCount = 0;
        // Sending
        InetAddress ip;
        DatagramSocket sendSocket = new DatagramSocket();

        while (true) {

            // receiveFile
            byte[] receiveFile = new byte[6000];
            DatagramPacket packet = new DatagramPacket(receiveFile, receiveFile.length);
            socket.receive(packet);
            ip = InetAddress.getByName(packet.getAddress().getHostAddress());
            System.out.println("Packet receiveFiled from : "+packet.getAddress().getHostAddress());

            CustomPacket pkt = new CustomPacket(receiveFile, packet.getLength());
            if((pkt.flags>>1|0)==1){
                System.out.println("FIN Packet");
                System.out.println("Sender Done Sending");
                //send a finAck packet
                byte[] finAckPayload = new byte[1];
                CustomPacket finAckPacket = new CustomPacket(pkt.sourceIpAddress, pkt.destinationIpAddress, pkt.totalFragments, pkt.fragmentNumber, finAckPayload);
                finAckPacket.setAck(1);
                finAckPacket.setFin(1);
                System.out.println("Sending FIN ACK to sender");

                byte[] finAckCustomPacketBytes = finAckPacket.getBytes();
                DatagramPacket ackPacket = new DatagramPacket(finAckCustomPacketBytes, finAckCustomPacketBytes.length, ip, 8432);
                sendSocket.send(ackPacket);

                break;
            }
            receiveFileCount++;
            // If the packet has already been receiveFiled then do nothing
            if (!packetsAdded.contains(pkt.fragmentNumber)) {
                packets.add(pkt.dataPayload);
                ByteBuffer fragmentNumberBuffer = ByteBuffer.wrap(pkt.fragmentNumber);
                fragmentNumberBuffer.order(ByteOrder.BIG_ENDIAN);
                packetsAdded.add(fragmentNumberBuffer.getInt());
            }

            ByteBuffer totalFragmentsBuffer = ByteBuffer.wrap(pkt.totalFragments);
            totalFragmentsBuffer.order(ByteOrder.BIG_ENDIAN);

            // Write to file if all the fragments have been receiveFiled
            if (receiveFileCount == totalFragmentsBuffer.getInt()) {
                writeBytesToFile();
            }

            // Send Acknowledgement
            byte[] ackPayload = new byte[1];
            ackPayload[0] = (byte) 0;
            CustomPacket ackCustomPacket = new CustomPacket(pkt.sourceIpAddress, pkt.destinationIpAddress, pkt.totalFragments, pkt.fragmentNumber, ackPayload);
            ackCustomPacket.setAck(1);
            //convert the packet source IP bytes to String
            System.out.println("Source:"+InetAddress.getByAddress(pkt.sourceIpAddress).getHostAddress());
            System.out.println("Destination:"+InetAddress.getByAddress(pkt.destinationIpAddress).getHostAddress());

            byte[] ackCustomPacketBytes = ackCustomPacket.getBytes();
            DatagramPacket ackPacket = new DatagramPacket(ackCustomPacketBytes, ackCustomPacketBytes.length, ip, 8432);
            sendSocket.send(ackPacket);

            ByteBuffer fragmentNumberBuffer = ByteBuffer.wrap(pkt.fragmentNumber);
            fragmentNumberBuffer.order(ByteOrder.BIG_ENDIAN);
            System.out.println("Sent ACK "+ackCustomPacket.flags+" for Packet Fragment "+fragmentNumberBuffer.getInt());

        }
    }




    public static void main(String args[]) {
        int roverId = Integer.parseInt(args[0]);
        ripPort = Integer.parseInt(args[1]);
        System.out.println("Router id:" + roverId);
        Rover r = new Rover(roverId);
        Thread receiveThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    r.receive();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        receiveThread.start();
        r.send();

    }


}