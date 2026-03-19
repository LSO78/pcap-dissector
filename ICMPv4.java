import java.nio.ByteBuffer;

/**
 * Représente un paquet ICMPv4
 */
public class ICMPv4 {
    private int type;
    private int code;
    private int checksum;
    private int identifier;
    private int sequenceNumber;
    private int unused;
    private byte[] originalIpHeaderAndPayload;

    /**
     * Constructeur
     * Lit le payload ICMPv4 pour extraire les informations
     * @param payload Le tableau d'octets contenant le paquet ICMPv4
     */
    public ICMPv4(byte[] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);

        type = buffer.get() & 0xFF;
        code = buffer.get() & 0xFF;
        checksum = buffer.getShort() & 0xFFFF;

        if (type == 8 || type == 0) {
            identifier = buffer.getShort() & 0xFFFF;
            sequenceNumber = buffer.getShort() & 0xFFFF;
        } else if (type == 3 || type == 11) {
            unused = buffer.getInt();
            originalIpHeaderAndPayload = new byte[8];
            buffer.get(originalIpHeaderAndPayload);
        }
    }

    /**
     * Affiche les informations du paquet ICMPv4
     */
    public void display() {
        System.out.println("                -- ICMPv4 Payload --");
        System.out.println("                Type : " + getTypeName());
        System.out.println("                Code : " + code);
        System.out.println("                Checksum : " + checksum);

        if (type == 8 || type == 0) {
            System.out.println("                Identifier : " + identifier);
            System.out.println("                Sequence Number : " + sequenceNumber);
        } else if (type == 3 || type == 11) {
            System.out.println("                Unused : " + unused);
        }
    }

    /**
     * Renvoie le type de message ICMPv4
     * @return Le nom du type de message ICMPv4
     */
    private String getTypeName() {
        switch (type) {
            case 0: return "Echo Reply (0)";
            case 3: return "Destination Unreachable (3)";
            case 5: return "Redirect Message (5)";
            case 8: return "Echo Request (8)";
            case 11: return "Time Exceeded (11)";
            case 12: return "Parameter Problem (12)";
            default: return "Unknown (" + type + ")";
        }
    }
}
