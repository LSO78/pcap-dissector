import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Représente un segment TCP et extrait les informations pertinentes
 */
public class TCP {
    private int sourcePort;
    private int destinationPort;
    private long sequenceNumber;
    private long acknowledgmentNumber;
    private int dataOffset;
    private boolean synFlag;
    private boolean ackFlag;
    private boolean finFlag;
    private boolean rstFlag;
    private boolean pshFlag;
    private boolean urgFlag;
    private int windowSize;
    private int checksum;
    private int urgentPointer;
    private int headerLength;
    private byte[] nextPayload;

    /**
     * Constructeur
     * Lit les données du payload TCP
     * @param payload Tableau d'octets contenant les données TCP
     */
    public TCP(byte[] payload) {

        ByteBuffer buffer = ByteBuffer.wrap(payload);

        sourcePort = buffer.getShort() & 0xFFFF;
        destinationPort = buffer.getShort() & 0xFFFF;
        sequenceNumber = buffer.getInt() & 0xFFFFFFFFL;
        acknowledgmentNumber = buffer.getInt() & 0xFFFFFFFFL;
        dataOffset = (buffer.get() >> 4) & 0x0F;
        
        int flags = buffer.get();
        synFlag = (flags & 0x02) != 0;
        ackFlag = (flags & 0x10) != 0;
        finFlag = (flags & 0x01) != 0;
        rstFlag = (flags & 0x04) != 0;
        pshFlag = (flags & 0x08) != 0;
        urgFlag = (flags & 0x20) != 0;

        windowSize = buffer.getShort() & 0xFFFF;
        checksum = buffer.getShort() & 0xFFFF;
        urgentPointer = buffer.getShort() & 0xFFFF;

        headerLength = (buffer.get() >> 4) * 4;
        buffer.position(headerLength);
        int nextPayloadLength = payload.length - headerLength;
        nextPayload = new byte[nextPayloadLength];
        buffer.get(nextPayload);
    }

    /**
     * Retourne une chaîne de caractères représentant les flags TCP
     * @return Chaîne contenant les indicateurs actifs
     */
    private String getFlags() {
        StringBuilder flags = new StringBuilder();
        if (synFlag) flags.append("SYN ");
        if (ackFlag) flags.append("ACK ");
        if (finFlag) flags.append("FIN ");
        if (rstFlag) flags.append("RST ");
        if (pshFlag) flags.append("PSH ");
        if (urgFlag) flags.append("URG ");
        return flags.toString().trim();
    }

     /**
     * Vérifie si le segment TCP est un paquet HTTP
     * @return true si c'est un paquet HTTP, false sinon
     */
    public boolean isHttpPacket() {
        return destinationPort == 80 || sourcePort==80;
    }

    /**
     * Vérifie si le segment TCP est un paquet FTP
     * @return true si c'est un paquet FTP, false sinon
     */
    public boolean isFtpPacket() {
        return (destinationPort == 21 || sourcePort == 21) && ackFlag && pshFlag;
    }

    /**
     * Affiche les lignes d'un paquet HTTP
     * @param httpPacket La chaîne contenant le paquet HTTP
     */
    public void printHttpPacket(String httpPacket){
        String[] httpLines = httpPacket.split("\r\n");
        for(String line : httpLines){
            System.out.println("                    " + line);
        }
    }

    /**
     * Affiche les lignes d'un paquet FTP
     * @param ftpPacket La chaîne contenant le paquet FTP
     */
    public void printFtpPacket(String ftpPacket) {
        String[] ftpLines = ftpPacket.split("\r\n");
        for (String line : ftpLines) {
            System.out.println("                    " + line);
        }
    }

    /**
     * Affiche les informations du segment TCP
     */
    public void display() {
        System.out.println("                -- TCP Payload --");
        System.out.println("                Source Port : " + sourcePort);
        System.out.println("                Destination Port : " + destinationPort);
        System.out.println("                Sequence Number : " + sequenceNumber);
        System.out.println("                Acknowledgment Number : " + acknowledgmentNumber);
        System.out.println("                Data Offset : " + (dataOffset * 4) + " octets");
        System.out.println("                Flags : " + getFlags());
        System.out.println("                Window Size : " + windowSize);
        System.out.println("                Checksum : " + checksum);
        System.out.println("                Urgent Pointer : " + urgentPointer);

        // Affichage spécifique pour les paquets HTTP et FTP
        if(isHttpPacket()){
            String payloadString = new String(nextPayload, StandardCharsets.UTF_8);
            System.out.println("                    -- HTTP payload --");
            printHttpPacket(payloadString);
        }
        if (isFtpPacket()) {
            String payloadString = new String(nextPayload, StandardCharsets.UTF_8);
            System.out.println("                    -- FTP payload --");
            printFtpPacket(payloadString);
        }
    }
}
