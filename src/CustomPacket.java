import java.util.ArrayList;

public class CustomPacket {
    private byte protocolNumber;
    byte[] sourceIpAddress = new byte[4];
    byte[] destinationIpAddress = new byte[4];
    byte[] totalFragments = new byte[4];
    byte flags;
    byte[] fragmentNumber = new byte[4];
    byte[] dataPayload;


    public CustomPacket(byte[] sourceIpAddress, byte[] destinationIpAddress, byte[] totalFragments, byte[] fragmentNumber, byte[] dataPayload) {
        this.protocolNumber = (byte) 77;
        this.sourceIpAddress = sourceIpAddress;
        this.destinationIpAddress = destinationIpAddress;
        this.totalFragments = totalFragments;
        this.flags = 0;
        this.fragmentNumber = fragmentNumber;
        this.dataPayload = dataPayload;

    }

    public CustomPacket() {

    }

    /**
     * This function sets the ack bit in the flags byte
     * @param ack value of ack to be set
     */

    public void setAck(int ack){
        this.flags = (byte)(ack|this.flags);
    }

    /**
     * This function sets the fin bit in the flags byte
     * @param fin value of fin to be set
     */
    public void setFin(int fin){
        this.flags = (byte)(this.flags|(fin<<1));
    }

    /**
     * This function creates a packet using the incoming byte stream and sets varibles for the packet according to
     * what arrived in the byte stream.
     *
     * @param incomingBytes bytes that are to be decoded
     * @param packetLength total length of the packet that was received
     */


    public CustomPacket(byte[] incomingBytes, int packetLength) {
        this.protocolNumber = incomingBytes[0];

        //source ip address
        this.sourceIpAddress[0] = incomingBytes[1];
        this.sourceIpAddress[1] = incomingBytes[2];
        this.sourceIpAddress[2] = incomingBytes[3];
        this.sourceIpAddress[3] = incomingBytes[4];

        //destination ip address
        this.destinationIpAddress[0] = incomingBytes[5];
        this.destinationIpAddress[1] = incomingBytes[6];
        this.destinationIpAddress[2] = incomingBytes[7];
        this.destinationIpAddress[3] = incomingBytes[8];

        this.totalFragments[0] = incomingBytes[9];
        this.totalFragments[1] = incomingBytes[10];
        this.totalFragments[2] = incomingBytes[11];
        this.totalFragments[3] = incomingBytes[12];

        this.flags = incomingBytes[13];

        this.fragmentNumber[0] = incomingBytes[14];
        this.fragmentNumber[1] = incomingBytes[15];
        this.fragmentNumber[2] = incomingBytes[16];
        this.fragmentNumber[3] = incomingBytes[17];

        this.dataPayload = new byte[packetLength - 18];

        for (int i = 0; i < packetLength - 18; i++) {
            this.dataPayload[i] = incomingBytes[i + 18];
        }
    }

    /**
     * The getBytes function returns the bytes that are present in the packet.
     *
     * @return array of bytes from the packet
     */

    public byte[] getBytes() {
        ArrayList<Byte> bytesToSend = new ArrayList<>();
        bytesToSend.add(this.protocolNumber);

        //source ip address
        bytesToSend.add(this.sourceIpAddress[0]);
        bytesToSend.add(this.sourceIpAddress[1]);
        bytesToSend.add(this.sourceIpAddress[2]);
        bytesToSend.add(this.sourceIpAddress[3]);

        //destination ip address
        bytesToSend.add(this.destinationIpAddress[0]);
        bytesToSend.add(this.destinationIpAddress[1]);
        bytesToSend.add(this.destinationIpAddress[2]);
        bytesToSend.add(this.destinationIpAddress[3]);

        bytesToSend.add(this.totalFragments[0]);
        bytesToSend.add(this.totalFragments[1]);
        bytesToSend.add(this.totalFragments[2]);
        bytesToSend.add(this.totalFragments[3]);

        bytesToSend.add(this.flags);

        bytesToSend.add(this.fragmentNumber[0]);
        bytesToSend.add(this.fragmentNumber[1]);
        bytesToSend.add(this.fragmentNumber[2]);
        bytesToSend.add(this.fragmentNumber[3]);


        for (int i = 0; i < dataPayload.length; i++) {
            bytesToSend.add(dataPayload[i]);
        }

        byte[] byteArrayToSend = new byte[bytesToSend.size()];
        for (int i = 0; i < bytesToSend.size(); i++) {
            byteArrayToSend[i] = bytesToSend.get(i);
        }
        return byteArrayToSend;
    }


}
