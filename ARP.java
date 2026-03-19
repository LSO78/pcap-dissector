import java.nio.ByteBuffer;

/**
 * Classe représentant le protocole ARP
 */
public class ARP {

    // Champs ARP
    private int protocolType;
    private short opcode;
    private boolean isIPv6;
    private byte[] sourceMAC = new byte[6];
    private byte[] destMAC = new byte[6];
    private byte[] sourceIPv4 = new byte[4];
    private byte[] destIPv4 = new byte[4];
    private byte[] sourceIPv6 = new byte[16];
    private byte[] destIPv6 = new byte[16];

    /**
     * Constructeur
     * Extrait les champs
     * @param payload Données du protocole
     */
    public ARP(byte[] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);

        buffer.position(2);
        protocolType = buffer.getShort() & 0xFFFF;

        buffer.position(6);
        opcode = buffer.getShort();

        buffer.position(8);
        buffer.get(sourceMAC);
        if(protocolType==0x0800){
            buffer.get(sourceIPv4);
            isIPv6 = false;
        } else if(protocolType==0x86DD){
            buffer.get(sourceIPv6);
            isIPv6 = true;
        }
        buffer.get(destMAC);
        if(isIPv6){
            buffer.get(destIPv6);
        } else {
            buffer.get(destIPv4);
        }
    }

    public void display() {
        System.out.println("            -- ARP Payload --");
        System.out.println("            Type de protocole : " + getProtocolType(protocolType));
        System.out.println("            Opcode : " + getOperationCode(opcode));
        System.out.println("            Adresse MAC Source : " + bytesToHex(sourceMAC));
        if(isIPv6){
            System.out.print("          Adresse IPv6 Source : ");
            printIPv6Address(sourceIPv6);
        } else {
            System.out.println("            Adresse IPv4 Source : " + printIPv4Address(sourceIPv4));
        }
        System.out.println("            Adresse MAC Destination : " + bytesToHex(destMAC));
        if(isIPv6){
            System.out.print("          Adresse IPv6 Destination : ");
            printIPv6Address(destIPv6);
        } else {
            System.out.println("            Adresse IPv4 Destination : " + printIPv4Address(destIPv4));
        }
        
    }

    private String getOperationCode(short opcode) {
        switch (opcode) {
            case 1: return "request (1)";
            case 2: return "reply (2)";
            default: return "Inconnu (" + opcode + ")";
        }
    }

    private String getProtocolType(int protocolType) {
        switch (protocolType) {
            case 0x0800: return "IPv4 (0x0800)";
            case 0x86DD: return "IPv6 (0x86DD)";
            default: return "Inconnu (" + protocolType + ")";
        }
    }

    private void printIPv6Address(byte[] address) {
        for (int i = 0; i < address.length; i += 2) {
            System.out.printf("%02X%02X", address[i], address[i + 1]);
            if (i < address.length - 2) System.out.print(":");
        }
        System.out.println();
    }

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

    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X:", b));
        }
        return sb.substring(0, sb.length() - 1);
    }
}
