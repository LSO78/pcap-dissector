import java.nio.ByteBuffer;

/**
 * Représente un paquet ICMPv4
 */
public class ICMPv6 {
    private int type;
    private int code;
    private int checksum;

    /**
     * Constructeur
     * Lit le payload ICMPv6 pour extraire les informations
     * @param payload Le tableau d'octets contenant le paquet ICMPv4
     */
    public ICMPv6(byte[] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);

        type = buffer.get() & 0xFF;
        code = buffer.get() & 0xFF;
        checksum = buffer.getShort() & 0xFFFF;
    }

    /**
     * Affiche les informations du paquet ICMPv6
     */
    public void display() {
        System.out.println("                -- ICMPv6 Payload --");
        System.out.println("                Type : " + getTypeName());
        System.out.println("                Code : " + code);
        System.out.println("                Checksum : " + checksum);
    }

    /**
     * Renvoie le type de message ICMPv6
     * @return Le nom du type de message ICMPv6
     */
    private String getTypeName() {
        switch (type) {
            case 1: return "Destination Unreachable (1)";
            case 2: return "Packet Too Big (2)";
            case 3: return "Time Exceeded (3)";
            case 128: return "Echo Request (128)";
            case 129: return "Echo Reply (129)";
            case 135: return "Neighbor Solicitation (135)";
            case 136: return "Neighbor Advertisement (136)";
            default: return "Unknown (" + type + ")";
        }
    }
}
