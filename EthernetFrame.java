import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * La classe EthernetFrame représente une trame Ethernet extraite d'un fichier PCAP
 * Elle analyse et stocke les adresses MAC source et destination, ainsi que le type de protocole encapsulé
 * Elle extrait également le payload associé à la trame Ethernet et permet de l'afficher
 */
public class EthernetFrame {

    private byte[] destMac = new byte[6];
    private byte[] sourceMac = new byte[6];
    byte[] payload;
    private int type;

    /**
     * Constructeur
     * Lit l'en-tête Ethernet depuis le fichier et extrait les adresses MAC et le type de protocole
     * @param file Le flux d'entrée contenant les données du fichier PCAP
     * @param inclLen La longueur incluse du payload de la trame Ethernet
     * @throws IOException En cas de problème de lecture des données
     */
    public EthernetFrame(FileInputStream file, int inclLen) throws IOException {
        if (inclLen < 14) {
            throw new IOException("InclLen trop court pour contenir une en-tête Ethernet.");
        }
        byte[] ethernetData = new byte[14];
        if (file.read(ethernetData) != 14) {
            throw new IOException("Impossible de lire l'en-tête Ethernet.");
        }
        
        ByteBuffer buffer = ByteBuffer.wrap(ethernetData);

        buffer.get(destMac);
        buffer.get(sourceMac);
        this.type = buffer.getShort() & 0xFFFF;

        int payloadSize = inclLen - 14; // 14 = adresse MAC Dest (6) + adresse MAC Src (6) + Type (2)
        payload = new byte[payloadSize];
        if (file.read(payload) != payloadSize) {
            throw new IOException("Impossible de lire le payload de la trame Ethernet.");
        }
    }

     /**
     * Retourne le nom du protocole encapsulé dans la trame Ethernet en fonction de son type
     * @return Une chaîne indiquant le type de protocole encapsulé
     */
    public String getTypelName() {
        switch (type) {
            case 0x0800: return "IPv4 (0x0800)";
            case 0x86DD: return "IPv6 (0x86DD)";
            case 0x0806: return "ARP (0x806)";
            default: return "Inconnu (" + type + ")";
        }
    }

    /**
     * Affiche les informations de l'en-tête Ethernet et les données encapsulés
     */
    public void display() {
        System.out.println("        -- Ethernet Frame --");
        System.out.println("        Adresse MAC Destination : " + bytesToHex(destMac));
        System.out.println("        Adresse MAC Source : " + bytesToHex(sourceMac));
        System.out.println("        Type : " + getTypelName());
        displayPayload();
    }

    /**
     * Affiche le contenu du payload en fonction du protocole encapsulé dans la trame Ethernet
     * Analyse les protocoles encapsulés tels que IPv4, IPv6, et ARP, et décode leurs contenus respectifs
     */
    public void displayPayload() {
        switch (type) {
            case 0x0800:
                IPv4 ipv4 = new IPv4(payload);
                ipv4.display();
                if (ipv4.getProtocolName().equals("TCP (6)")) {
                    TCP tcp = new TCP(ipv4.getPayload());
                    tcp.display();
                } else if (ipv4.getProtocolName().equals("UDP (17)")){
                    UDP udp = new UDP(ipv4.getPayload());
                    udp.display();
                } else if (ipv4.getProtocolName().equals("ICMPv4 (1)")){
                    ICMPv4 icmp = new ICMPv4(ipv4.getPayload());
                    icmp.display();
                }
                break;
            case 0x86DD:
                IPv6 ipv6 = new IPv6(payload);
                ipv6.display();
                if (ipv6.getProtocolName().equals("TCP (6)")) {
                    TCP tcp = new TCP(ipv6.getPayload());
                    tcp.display();
                } else if (ipv6.getProtocolName().equals("UDP (17)")){
                    UDP udp = new UDP(ipv6.getPayload());
                    udp.display();
                } else if (ipv6.getProtocolName().equals("ICMPv6 (58)")){
                    ICMPv6 icmp = new ICMPv6(ipv6.getPayload());
                    icmp.display();
                }
                break;
            case 0x0806:
                ARP arp = new ARP(payload);
                arp.display();
                break;
            default:
                System.out.println("Protocole non supporté");
        }
    }

    /**
     * Utilisé pour afficher les adresses MAC sous forme lisible
     * @param bytes Tableau d'octets représentant une adresse MAC
     * @return La chaîne formatée en hexadécimal de l'adresse MAC
     */
    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X:", b));
        }
        return sb.substring(0, sb.length() - 1);
    }
}
