/**
 * This is a class which represents a Routing table entry for a particular rover.
 *
 * @author Poornima Sapkal
 */
class RouterTableEntry {
    byte[] addressFamilyIdentifier; // 2 bytes
    byte[] routeTag; // 2 bytes
    String ipAddress; // 4 bytes
    byte[] subnetMask; // 4 bytes
    String nextHop; // 4 bytes
    byte[] metric; // 4 bytes

    /**
     * Constructor for RouterTableEntry. It initializes the addressFamilyIdentifier, routeTag, subnetMask and metric.
     */
    public RouterTableEntry() {
        this.addressFamilyIdentifier = new byte[2];
        this.routeTag = new byte[2];
        this.subnetMask = new byte[4];
        this.metric = new byte[4];
    }


}