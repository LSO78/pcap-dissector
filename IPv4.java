import java.nio.ByteBuffer;

/**
 * Représente un paquet IPv4
 */
public class IPv4 {

    private int versionAndIHL;          // Version et IHL
    private int version;                 // Version IP
    private int IHL;                     // Internet Header Length
    private int IhlInOctets;             // IHL en octets
    private int typeOfService;           // Type de service
    private int totalLength;             // Longueur totale
    private int identification;          // Identification
    private int flags;                   // Drapeaux
    private int fragmentOffset;          // Décalage de fragment
    private int ttl;                     // Time to Live
    private byte protocol;               // Protocole
    private int headerChecksum;          // Checksum de l'en-tête
    private byte[] sourceAddress = new byte[4];  // Adresse IP source
    private byte[] destinationAddress = new byte[4]; // Adresse IP destination
    private byte[] nextPayload; 
    
    /**
     * Constructeur
     * Lit le payload IPv4 pour extraire les informations
     * @param payload Le tableau d'octets contenant le paquet IPv4
     */
    public IPv4(byte[] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);

        versionAndIHL = buffer.get();
        version = (versionAndIHL >> 4);
        IHL = versionAndIHL & 0x0F;
        IhlInOctets = IHL * 4;

        typeOfService = buffer.get();
        totalLength = buffer.getShort() & 0xFFFF;
        identification = buffer.getShort() & 0xFFFF;

        int flagsAndOffset = buffer.getShort() & 0xFFFF;
        flags = (flagsAndOffset >> 13) & 0x07;
        fragmentOffset = flagsAndOffset & 0x1FFF;

        ttl = buffer.get() & 0xFF;
        protocol = buffer.get();
        headerChecksum = buffer.getShort() & 0xFFFF;

        buffer.get(sourceAddress);
        buffer.get(destinationAddress);

        buffer.position(IhlInOctets);
        nextPayload = new byte[getPayloadLength()];
        buffer.get(nextPayload);
    }

    /**
     * Renvoie le nom du protocole de la couche supérieure
     * @return Le nom du protocole
     */
    public String getProtocolName() {
        switch (protocol & 0xFF) {
            case 1: return "ICMPv4 (1)";
            case 6: return "TCP (6)";
            case 17: return "UDP (17)";
            default: return "Inconnu (" + (protocol & 0xFF) + ")";
        }
    }

    public int getPayloadLength(){
        return totalLength - IhlInOctets;
    }

    public byte[] getPayload() {
        return nextPayload;
    }

    /**
     * Affiche les informations du paquet IPv4
     */
    public void display() {
        System.out.println("            -- IPv4 Payload --");
        System.out.println("            Version : " + version);
        System.out.println("            IHL : " + IhlInOctets + " octets");
        System.out.println("            Type of Service : " + typeOfService);
        System.out.println("            Total length : " + totalLength + " octets");
        System.out.println("            Identification : " + identification);
        System.out.println("            Flags : " + flags);
        System.out.println("            Fragment Offset : " + fragmentOffset);
        System.out.println("            TTL : " + ttl);
        System.out.println("            Protocol : " + getProtocolName());
        System.out.println("            Header Checksum : " + headerChecksum);
        System.out.println("            Adresse IPv4 Source : " + printIPv4Address(sourceAddress));
        System.out.println("            Adresse IPv4 Destination : " + printIPv4Address(destinationAddress));
    }

    /**
     * Retourne une adresse IPv4 en une chaîne de caractères
     * @param bytes Le tableau d'octets représentant l'adresse
     * @return La représentation sous forme de chaîne de l'adresse IPv4
     */
    public String printIPv4Address(byte[] bytes) {        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(bytes[i] & 0xFF); 
            if (i < bytes.length - 1) {
                sb.append(".");
            }
        }
        return sb.toString();
    }
}
