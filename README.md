# IST
Before any of this, in the node folder, configure the global_vars seed_ipv4_address variable to be the ipv4_address of the seed node, and the same with the port.

To run this project, you must first run api.py in the seed node folder with the -r flag after:
(python api.py -r)

Then to connect to it with other nodes, you run api.py in the node folder with the -br flag after:
(python api.py -br)

To further add more nodes, simply copy the directory (cp -r node new_node), and repeat the connecting steps.
