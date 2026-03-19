import java.nio.ByteBuffer;

/**
 * Représente un paquet IPv6
 */
public class IPv6 {
    
    private int version;
    private int trafficClass;
    private int flowLabel; 
    private int payloadLength;
    private int nextHeader;
    private int hopLimit;
    private byte[] sourceAddress = new byte[16];
    private byte[] destinationAddress = new byte[16];
    private byte[] nextPayload;

    /**
     * Constructeur
     * Lit le payload IPv6 pour extraire les informations
     * @param payload Le tableau d'octets contenant le paquet IPv6
     */
    public IPv6(byte[] payload) {
        
        ByteBuffer buffer = ByteBuffer.wrap(payload);

        int firstByte = buffer.get();
        version = (firstByte >>> 4) & 0x0F;

        int secondByte = buffer.get();
        trafficClass = ((firstByte & 0x0F) << 4) | ((secondByte >>> 4) & 0x0F);
        flowLabel = ((secondByte & 0x0F) << 16) | (buffer.getShort() & 0xFFFF);

        payloadLength = buffer.getShort() & 0xFFFF;
        nextHeader = buffer.get() & 0xFF;
        hopLimit = buffer.get() & 0xFF;

        buffer.get(sourceAddress);
        buffer.get(destinationAddress);

        nextPayload = new byte[payloadLength];
        buffer.get(nextPayload);
    }

    /**
     * Renvoie le nom du protocole de la couche supérieure
     * @return Le nom du protocole
     */
    public String getProtocolName() {
        switch (nextHeader) {
            case 6: return "TCP (6)";
            case 17: return "UDP (17)";
            case 58: return "ICMPv6 (58)";
            default: return "Extension non pris en compte (" + nextHeader + ")";
        }
    }

    public byte[] getPayload() {
        return nextPayload;
    }


    /**
     * Affiche les informations du paquet IPv6
     */
    public void display() {
        System.out.println("            -- IPv6 Payload --");
        System.out.println("            Version : " + version);
        System.out.println("            Traffic Class : " + trafficClass);
        System.out.println("            Flow Label : " + flowLabel);
        System.out.println("            Payload Length : " + payloadLength + " octets");
        System.out.println("            Next Header : " + getProtocolName());
        System.out.println("            Hop Limit : " + hopLimit);
        System.out.print("            Adresse IPv6 Source : ");
        printIPv6Address(sourceAddress);
        System.out.print("            Adresse IPv6 Destination : ");
        printIPv6Address(destinationAddress);
    }

    
    /**
     * Retourne une adresse IPv6 en une chaîne de caractères
     * @param bytes Le tableau d'octets représentant l'adresse
     * @return La représentation sous forme de chaîne de l'adresse IPv6
     */
    private void printIPv6Address(byte[] address) {
        for (int i = 0; i < address.length; i += 2) {
            System.out.printf("%02X%02X", address[i], address[i + 1]);
            if (i < address.length - 2) System.out.print(":");
        }
        System.out.println();
    }
}
