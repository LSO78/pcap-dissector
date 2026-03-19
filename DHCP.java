import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Classe représentant le protocle DHCP
 */
public class DHCP {
    private int op;
    private int htype;
    private int hlen;
    private int hops;
    private int xid;
    private int secs;
    private int flags;
    private String ciaddr;
    private String yiaddr;
    private String siaddr;
    private String giaddr;
    private String chaddr;
    private String sname;
    private String file;
    private byte[] options;

    /**
     * Constructeur
     * Extrait les champs
     * @param payload Données du protocole
     */
    public DHCP(byte[] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);

        op = buffer.get() & 0xFF; // & 0xFF -> valeurs non signées 
        htype = buffer.get() & 0xFF; 
        hlen = buffer.get() & 0xFF; 
        hops = buffer.get() & 0xFF;
        xid = buffer.getInt();
        secs = buffer.getShort() & 0xFFFF; // & 0xFFFF -> valeurs non signées
        flags = buffer.getShort() & 0xFFFF;
        ciaddr = formatIp(buffer.getInt());
        yiaddr = formatIp(buffer.getInt());
        siaddr = formatIp(buffer.getInt());
        giaddr = formatIp(buffer.getInt());

        byte[] chaddrBytes = new byte[16];
        buffer.get(chaddrBytes);
        chaddr = formatHardwareAddress(chaddrBytes);

        byte[] snameBytes = new byte[64];
        buffer.get(snameBytes);
        sname = new String(snameBytes, StandardCharsets.UTF_8).trim();

        byte[] fileBytes = new byte[128];
        buffer.get(fileBytes);
        file = new String(fileBytes, StandardCharsets.UTF_8).trim();

        int optionsLength = payload.length - buffer.position();
        options = new byte[optionsLength];
        buffer.get(options);
    }

    private String formatIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." + 
               ((ip >> 16) & 0xFF) + "." + 
               ((ip >> 8) & 0xFF) + "." + 
               (ip & 0xFF);
    }
    

    private String formatHardwareAddress(byte[] address) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < address.length; i++) {
            sb.append(String.format("%02X", address[i]));
            if (i < address.length - 1) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    public void display() {
        System.out.println("                -- DHCP Payload --");
        System.out.println("                Operation : " + op);
        System.out.println("                Hardware Type : " + htype);
        System.out.println("                Hardware Length : " + hlen);
        System.out.println("                Hops : " + hops);
        System.out.println("                Transaction ID : " + xid);
        System.out.println("                Seconds Elapsed : " + secs);
        System.out.println("                Flags : " + flags);
        System.out.println("                Client IP : " + ciaddr);
        System.out.println("                Your IP : " + yiaddr);
        System.out.println("                Server IP : " + siaddr);
        System.out.println("                Gateway IP : " + giaddr);
        System.out.println("                Client Hardware Address : " + chaddr);
        System.out.println("                Server Name : " + sname);
        System.out.println("                Boot File Name : " + file);
    }
}
