# Firewall
Coding Assessment 2019-2020 - Illumio PCE 2019

2------------

a. I tested my solution using the example inputs from the coding challenges. I also added a single edge case as I was running out of time. 
The test cases are included in the main method of the Firewall class.
If I had more time, I would have implemented a more sophisticated test suite using JUnit. I would add more test csv's with edge cases like
small ranges, invalid inputs, and one-off errors.

b. I decided to not implement a more memory efficient algorithm by combining ranges because it would make the runtime a lot longer. So,
I decided to instead save every new rule as a separate range in four bins. Each bin represents udp/tcp or ingoing/outgoing rule.
Each bin has port ranges, wherein each port range has ip addresses in that rule. 

I decided to use ranges instead of storing each port and ip address combination because that would be a memory inefficient algorithm, despite
the quick runtime performance from having a direct access to a specific rule. 

I decided to make ip addresses 32 bits by using the Integer class and using the compareUnsigned method from the java standard library. I did
this instead of making separate groups for the 8-bit parts of the IPv4 address because each address could be represented as 32 bits. By doing
this I could save memory by reducing memory allocation by 1/4 instead of keeping each part as an integer. This method increases runtime by using the
compareUnsigned method to see if the ip addresses are within a specific range, instead of trying to check if each 8-bit part of an ip address is within 
a range of an ip address.

c. An optimization would be to instead of using an ArrayList to store the four types of rules. I could use a Map implementation
that will automatically map a specific type to an ArrayList. This would be slightly better runtime because I would have to compute
the specific position within each input in the csv file. Instead, it would be more clear as to what rule the packet would belong to
instead of either index 0,1,2,3 of the arraylist. 

Another optimization would be to separate ranges from single ports/ip addresses. The problem with inputting individual ip/ports into
a range class is that the range rule would essentially have the same memory allocation and runtime analysis as a single rule. So there are
unneccesary space that is used up for single rules. 

A last optimization would be to make better and more sophisticated test scripts/suites using JUnit. I did not have a lot of time to make test
scripts, so I tested only one edge case and the cases given on the coding challenge document. I really wish I could include more edge cases. Another
problem would be that if the inputs were not as clean as the document said, I would have to check for more invalid inputs. An example
would be an invalid range like 200-150. So another optimization would be to check for these invalid inputs.

d. I would like to thank the reviewer for taking their time looking over my code and hope to hear back some other great design
ideas and optimizations that I have not listed. 

3-------

I am interested in both the platform and data team. My rankings would be: 1. Platform team 2. Data team 3. Policy Team.
