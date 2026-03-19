import java.nio.ByteBuffer;

/**
 * Représente un segment UDP et extrait les informations pertinentes
 */
public class UDP {
    private int sourcePort;
    private int destinationPort;
    private int length;
    private int checksum;
    private int payloadLength;
    private byte[] nextPayload;

    /**
     * Constructeur
     * Lit les données du payload UDP
     * @param payload Tableau d'octets contenant les données UDP
     */
    public UDP(byte[] payload){
        ByteBuffer buffer = ByteBuffer.wrap(payload);

        sourcePort = buffer.getShort() & 0xFFFF;
        destinationPort = buffer.getShort() & 0xFFFF;
        length = buffer.getShort() & 0xFFFF;
        checksum = buffer.getShort() & 0xFFFF;
        payloadLength = length - 8;

        nextPayload = new byte[payloadLength];
        buffer.get(this.nextPayload);
    }

    /**
     * Vérifie si le segment UDP est un paquet DHCP
     * @return true si c'est un paquet DHCP, false sinon
     */
    public boolean isDhcpPacket() {
        return (destinationPort == 67 || sourcePort == 67 || destinationPort == 68 || sourcePort == 68);
    }

    /**
     * Affiche les informations d'un paquet DHCP
     */
    public void displayDhcpPacket() {
        DHCP dhcpPacket = new DHCP(nextPayload);
        dhcpPacket.display();
    }

    /**
     * Affiche les informations du segment UDP
     */
    public void display() {
        System.out.println("                -- UDP Payload --");
        System.out.println("                Source Port : " + sourcePort);
        System.out.println("                Destination Port : " + destinationPort);
        System.out.println("                Total Length : " + length + " octets"); 
        System.out.println("                Checksum : " + checksum);
        System.out.println("                Payload Size : " + payloadLength + " octets");
        if(isDhcpPacket()){
            displayDhcpPacket();
        }
    }
}