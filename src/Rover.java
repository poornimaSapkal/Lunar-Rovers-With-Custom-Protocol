import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
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