import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;
import java.lang.Integer;
import static java.lang.Integer.compareUnsigned;

public class Firewall {

    // A 4x1 table, [0] = tcp, ingoing; [1] = tcp, outgoing; [2] = udp, ingoing; [3] = udp,outgoing; If i had time, I would
    // might've used a well structured hashmap instead of using an ArrayList so I would not have to process the strings every time
    // so that I have to keep track of the specific positions of specific rules.
    ArrayList<ArrayList<PortRange>> ports;
    Firewall(String filename) {
        File csvFile = new File(filename);
        Scanner input;
        ports = new ArrayList<>();

        // Adds four new lists
        ports.add(new ArrayList<PortRange>());
        ports.add(new ArrayList<PortRange>());
        ports.add(new ArrayList<PortRange>());
        ports.add(new ArrayList<PortRange>());
        try {
            input = new Scanner(csvFile);


            // For each line in the csv
            while(input.hasNextLine()) {
                int position = 0;
                String[] inputs = input.nextLine().split(",");

                // sets the position to check outgoing/ingoing or udp/tcp rules
                if(inputs[0].equals("outgoing")) {
                    position += 1;
                }
                if(inputs[1].equals("udp")) {
                    position += 2;
                }

                Integer startingPort;
                Integer endingPort;
                // Sees if ports are not a range
                if(!inputs[2].contains("-")) {
                    startingPort = Integer.parseInt(inputs[2]);
                    endingPort = Integer.parseInt(inputs[2]);
                } else {
                    String[] rangeSplit = inputs[2].split("-");
                    startingPort = Integer.parseInt(rangeSplit[0]);
                    endingPort = Integer.parseInt(rangeSplit[1]);
                }


                Integer startingIP;
                Integer endingIP;

                // Sees if ip addresses are not a range
                if(!inputs[3].contains("-")) {
                    startingIP = changeIPtoInteger(inputs[3]);
                    endingIP = changeIPtoInteger(inputs[3]);
                } else {
                    String[] rangeSplit = inputs[3].split("-");
                    startingIP = changeIPtoInteger(rangeSplit[0]);
                    endingIP = changeIPtoInteger(rangeSplit[1]);
                }

                PortRange newRange = new PortRange(startingPort, endingPort);
                newRange.ipAddressRange = new IPAddressRange(startingIP, endingIP);
                ports.get(position).add(newRange);

                /* I don't think i have time to make an algorithm that will check for duplicate ranges (i.e. ports: 100- 200 and 150- 250)
                 * But if I did, I would update the ranges so that they would fit specific cases. For example, if 100-200
                 * had 192.x.x.x but 150-250 has 190.x.x.x, i would have to make an algorithm that would let 100-150 ports
                 * contain only 192.x.x.x addresses, 150-200 to have both 190 and 192 ips, and 200-250 to have 190.x.x.x addresses
                 * so that we only have to change one range for it instead of checking all of the ranges in the arraylist.
                 * For now, each input has its own range, which makes the runtime a lot faster, but uses more memory.
                 */

            }
        } catch (FileNotFoundException ex){
            System.out.print("File not found");
            System.exit(1);
        }
    }

    // Checks if the specific packet if in the ranges specified by the firewall object.
    public boolean accept_packet(String direction, String protocol, Integer port, String ip_address) {
        // A 4x1 table, [0] = tcp, ingoing; [1] = tcp, outgoing; [2] = udp, ingoing; [3] = udp,outgoing
        int position = 0;

        // sets the position to check outgoing/ingoing or udp/tcp rules
        if(direction.equals("outgoing")) {
            position += 1;
        }
        if(protocol.equals("udp")) {
            position += 2;
        }

        ArrayList<PortRange> listOfPortRanges = ports.get(position);
        if(listOfPortRanges.isEmpty()) {
            return false;
        }

        // Checks all the ranges for the port and address.
        for(int i = 0; i < listOfPortRanges.size(); i++) {
            if(listOfPortRanges.get(i).containsPort(port)) {
                Integer ipAddressToInt = changeIPtoInteger(ip_address);
                if(listOfPortRanges.get(i).ipAddressRange.containsIPAddress(ipAddressToInt)) {
                    return true;
                }
            }
        }

        return false;

    }


    // Class PortRange just contains the range for a specific udp/tcp ingoing/outgoing rule
    class PortRange {
        Integer startPort;
        Integer endPort;
        public IPAddressRange ipAddressRange;

        PortRange(Integer startPort, Integer endPort){
            this.startPort = startPort;
            this.endPort = endPort;
        }
        public boolean containsPort(Integer portNumber) {
            return compareUnsigned(portNumber, endPort) <= 0 && compareUnsigned(portNumber, startPort) >= 0;
        }

        /* Both methods below are not used but would be helpful in another implementation by reducing memory by concatenating ranges*/

        // Sees if the port in question is less than the starting port
        public boolean isLessThanRange(Integer port) {
            return compareUnsigned(port, startPort) <= 0;
        }

        // Sees if the port in question is greater than the ending port.
        public boolean isGreaterThanRange(Integer port) {
            return compareUnsigned(port, endPort) >= 0;
        }

    }
    // Ip addresses can be represented by a 32-bit integer.
    // for 500k entries, 32 bits is 2MB, which is not a lot.
    // Java SE 8 has compareUnsigned to compare unsigned ints, can be used to find range of ip addresses.
    class IPAddressRange {
        Integer startIP;
        Integer endIP;

        IPAddressRange(Integer startIP, Integer endIP){
            this.startIP = startIP;
            this.endIP = endIP;
        }


        public boolean containsIPAddress(Integer ipAddress) {
            return compareUnsigned(ipAddress, startIP) >= 0 && compareUnsigned(ipAddress, endIP) <= 0;
        }

        /* Both methods below are not used but would be helpful in another implementation by reducing memory by concatenating ranges*/

        // Sees if the ip in question is less than the starting ip
        public boolean isLessThanRange(Integer ipAddress) {
            return compareUnsigned(ipAddress, startIP) <= 0;
        }

        // Sees if the ip in question is greater than the ending ip
        public boolean isGreaterThanRange(Integer ipAddress) {
            return compareUnsigned(ipAddress, endIP) >= 0;
        }
    }

    // Allows changing the ip address to integers as 32bit representations
    public Integer changeIPtoInteger(String ipAddress) {
        Integer ipAddressAsInteger = 0;

        // . has special meaning for regexes, so we must use \\. in order to get the '.' character.
        // https://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html#sum
        String[] ipAddressParts = ipAddress.split("\\.");

        // Modify ip address to bit-wise representation as integer
        for(int i = 0; i < ipAddressParts.length; i++) {
            Integer ipAddressPart = Integer.parseInt(ipAddressParts[i]);
            // In order to multiply the integer to fit its bit-wise position, I would have to shift the first part 24 bits,
            // the second part 16 bits, third part 8 bits, and the last part 0 bits. In addition, the 0th position is the first part,
            // 1st position is the second part, etc.
            ipAddressAsInteger  += ipAddressPart << (24 - 8 * i);
        }
        return ipAddressAsInteger;
    }
    public static void main(String[] args) {
        Firewall fw = new Firewall("test.csv");
        System.out.println(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")); // true
        System.out.println(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")); // true
        System.out.println(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")); // true
        System.out.println(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")); // false
        System.out.println(fw.accept_packet("inbound", "udp", 24, "52.12.48.92")); // false
        System.out.println(fw.accept_packet("inbound", "udp", 54, "242.245.245.222")); // true
        System.out.println(fw.accept_packet("inbound", "udp", 54, "255.255.255.255")); // false, tests the edge case

    }

}
