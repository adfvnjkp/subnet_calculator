"""
Usage guideline:
run this file(subnet_calculator.py).
Enter an ip address and a number of subnets
This program will check if the input is valid. If not, this program will raise error.
If the input is valid, this program will print out the following:
The current network, mask, range of addresses and a possible high and low router address.
The number of bits needed to be stolen
The new subnet mask in binary and base 10 numbers.
The number of subnets created
The total number of hosts per subnet
The subnet range for the first 5 subnets or the number of requested subnets in binary and decimal numbers
The subnet range for the last subnet – in binary and decimal numbers
The range of usable addresses in each
Possible low and high router addresses for each subnet
Identify the network IDs and the broadcast address

author: Tuanzhang Li (tl7587@rit.edu)
"""

def check_ip_address(ip_address):
    """
    check if the ip address from the input is valid
    :param ip_address: the input ip address
    """
    for i in ip_address:
        if not 0 <= int(i) <= 255:
            raise ValueError("IPV4 address invalid: bytes should be between 0 and 255")
    if int(ip_address[0]) > 223:
        raise ValueError("Invalid IPV4 address1")
    # if int(ip_address[0]) == 127 or 169:
    #     raise ValueError("Invalid IPV4 address2")
    # if int(ip_address[1]) == 254:
    #     raise ValueError("Invalid IPV4 address3")
    if len(ip_address) != 4:
        raise ValueError("IPV4 address invalid: not exactly 4 bytes.")


def mask_for_ip(ip_address):
    """
    generate a subnet mask for ip
    :param ip_address: the input ip address
    :return: mask address
    """
    # Assume ip_address[0] is not greater than 223.
    if 0 <= int(ip_address[0]) <= 127:
        return "255.0.0.0"
    elif 128 <= int(ip_address[0]) <= 191:
        return "255.255.0.0"
    else:
        return "255.255.255.0"


def convert_to_binary(decimal_address):
    """
    convert address from decimal to binary
    :param address: decimal ip or mask address
    :return: binary address
    """
    binary_ip = ['{0:08b}'.format(int(i)) for i in decimal_address]
    return "".join(binary_ip)


def convert_to_decimal(bin_address):
    """
    convert address from binary to decimal
    :param bin_address: binary ip or mask address
    :return: decimal address
    """
    bin_address.split(".")
    ip = ""
    for i in range(0, len(bin_address), 8):
        ip += str(int(bin_address[i:i + 8], 2)) + "."
    return ip[:-1]


def binary_address(address):
    """
    add dots to address
    """
    return address[:8] + "." + address[8:16] + "." + address[16:24] + "." + address[24:]


def is_power_of_two(n):
    """
    check if n is the power of 2
    """
    if n == 0:
        return False
    while n != 1:
        if n % 2 != 0:
            return False
        n = n // 2
    return True


def check_number_of_subnets(bin_address, input_number):
    """
    check if the number of subnets is valid
    :param bin_address: mask address in binary
    :param input_number: the input number of subnets from user
    """
    zeros = bin_address.count("0")
    if not 0 <= int(input_number) <= abs(2 ** zeros - 2):
        raise ValueError("Invalid number of subnets")
    if not is_power_of_two(int(input_number)):
        raise ValueError("Invalid number of subnets")


def and_process(decimal_ip, decimal_mask):
    """
    And calculation between the ip and mask address
    """
    return int(decimal_ip) & int(decimal_mask)


def current_network(ip_address, mask_address):
    """
    current network address by AND calculation
    """
    return '.'.join(str(and_process(ip_address[i], mask_address[i])) for i in range(4))


def current_mask(address):
    return '.'.join([str(i) for i in address])


def bin_stolen_bits(converted_quantity, bits_length):
    """
    returns binary stolen bits in the bit length
    :param converted_quantity: how many to be converted
    :param bits_length: length of Number of bits
    :return: binary string of stolen bits
    """
    zeros = bits_length - len("{0:b}".format(int(converted_quantity)))
    zeros_str = ""
    if zeros > 0:
        zeros_str = zeros * "0"
    return zeros_str + "{0:b}".format(int(converted_quantity))


def calculate_network_bin_id(network_bin_id, converted_quantity, subnet_bits, bits_length, host_bits):
    """
    calculates the binary network Id
    :param network_bin_id: former Network Id
    :param converted_quantity: how many to be converted
    :param subnet_bits: former network bits
    :param bits_length: length of Number of bits
    :param host_bits: number of new host bits
    :return: the binary network Id
    """
    bin_network_id = ""
    for i in range(subnet_bits):
        bin_network_id += network_bin_id[i]
    bin_network_id += bin_stolen_bits(converted_quantity, bits_length)
    bin_network_id += host_bits * "0"

    return bin_network_id


def calculate_broadcast_bin_address(network_bin_id, converted_quantity, subnet_bits, bits_length, host_bits):
    """
    calculates the binary broadcast address
    :param network_bin_id: former Network Id
    :param converted_quantity: how many to be converted
    :param subnet_bits: former network bits
    :param bits_length: length of Number of bits
    :param host_bits: number of new host bits
    :return: the binary broadcast address
    """
    bin_network_id = ""
    for i in range(subnet_bits):
        bin_network_id += network_bin_id[i]
    bin_network_id += bin_stolen_bits(converted_quantity, bits_length)
    bin_network_id += host_bits * "1"

    return bin_network_id


def requested_n_subnets(number_of_subnets, ip, mask, n):
    """
    find the first number of requested subnets and/or last subnets and print them
    :param number_of_subnets: input number_of_subnets from user
    :param ip: input ip address from user
    :param mask: calculated mask address from the input ip address
    :param n: number of requested subnets
    :return: the calculated subnets
    """
    bits_length = int(number_of_subnets - 1).bit_length()
    bin_ip = convert_to_binary(ip)
    bin_mask = convert_to_binary(mask)
    subnet_bits = bin_mask.count("1")
    final_subnet_bits = subnet_bits + bits_length
    final_host_bits = 32 - final_subnet_bits
    final_binary_mask = ""
    for i in range(final_subnet_bits):
        final_binary_mask += "1"
    for i in range(final_host_bits):
        final_binary_mask += "0"
    final_mask = convert_to_decimal(final_binary_mask)
    subnets = ''
    subnets += "{} subnets is created by {} stolen bits.\n".format(''.join(str(number_of_subnets)),
                                                                   ''.join(str(bits_length)))
    subnets += "Each subnet mask of following is {}, {} in binary.\n".format(''.join(final_mask),
                                                                             ''.join(binary_address(final_binary_mask)))
    subnets += "The total number of hosts per subnet is " + str(number_of_subnets) + ".\n\n"
    subnets += "The first " + str(n) + " subnets and/or last subnets are shown as follows."
    if number_of_subnets <= n:
        for i in range(number_of_subnets):
            network_bin_id = calculate_network_bin_id(bin_ip, i, subnet_bits, bits_length, final_host_bits)
            network_id = convert_to_decimal(network_bin_id)
            broadcast_bin_id = calculate_broadcast_bin_address(bin_ip, i, subnet_bits, bits_length, final_host_bits)
            broadcast_id = convert_to_decimal(broadcast_bin_id)
            possible_low_bin_addr = str((int(network_bin_id) + 1))
            possible_high_bin_addr = str((int(broadcast_bin_id) - 1))
            possible_low_addr = convert_to_decimal(possible_low_bin_addr)
            possible_high_addr = convert_to_decimal(possible_high_bin_addr)
            subnets += "\nCurrent network ID is {}, \nIn binary, {}.\n".format(''.join(network_id),
                                                                               ''.join(binary_address(network_bin_id)))
            subnets += "The decimal range is from " + str(network_id) + " to " + str(broadcast_id) + "\n"
            subnets += "The binary range is from " + str(binary_address(network_bin_id)) + " to " \
                       + str(binary_address(broadcast_bin_id)) + "\n"
            subnets += "The decimal range of usable address is from " + str(possible_low_addr) + " to " \
                       + str(possible_high_addr) + "\n"
            subnets += "The binary range is of usable address from " + str(binary_address(possible_low_bin_addr)) + " to " \
                       + str(binary_address(possible_high_bin_addr)) + "\n"
            subnets += "The decimal possible low and high router address are {}, and {}.\n".format(
                ''.join(possible_low_addr),
                ''.join(possible_high_addr))
            subnets += "The binary possible low and high router address are {}, and {}.\n".format(
                ''.join(binary_address(possible_low_bin_addr)),
                ''.join(binary_address(possible_high_bin_addr)))
            subnets += "The decimal network ID and broadcast address are {}, and {}.\n".format(
                ''.join(network_id),
                ''.join(broadcast_id))
            subnets += "The binary network ID and broadcast address are {}, and {}.\n".format(
                ''.join(binary_address(network_bin_id)),
                ''.join(binary_address(broadcast_bin_id)))
    else:
        for i in range(n):
            network_bin_id = calculate_network_bin_id(bin_ip, i, subnet_bits, bits_length, final_host_bits)
            network_id = convert_to_decimal(network_bin_id)
            broadcast_bin_id = calculate_broadcast_bin_address(bin_ip, i, subnet_bits, bits_length, final_host_bits)
            broadcast_id = convert_to_decimal(broadcast_bin_id)
            possible_low_bin_addr = str((int(network_bin_id) + 1))
            possible_high_bin_addr = str((int(broadcast_bin_id) - 1))
            possible_low_addr = convert_to_decimal(possible_low_bin_addr)
            possible_high_addr = convert_to_decimal(possible_high_bin_addr)
            subnets += "\nCurrent network ID is {}, \nIn binary, {}.\n".format(''.join(network_id),
                                                                               ''.join(binary_address(network_bin_id)))
            subnets += "The decimal range is from " + str(network_id) + " to " + str(broadcast_id) + "\n"
            subnets += "The binary range is from " + str(binary_address(network_bin_id)) + " to " \
                       + str(binary_address(broadcast_bin_id)) + "\n"
            subnets += "The decimal range of usable address is from " + str(possible_low_addr) + " to " \
                       + str(possible_high_addr) + "\n"
            subnets += "The binary range is of usable address from " + str(
                binary_address(possible_low_bin_addr)) + " to " \
                       + str(binary_address(possible_high_bin_addr)) + "\n"
            subnets += "The decimal possible low and high router address are {}, and {}.\n".format(
                ''.join(possible_low_addr),
                ''.join(possible_high_addr))
            subnets += "The binary possible low and high router address are {}, and {}.\n".format(
                ''.join(binary_address(possible_low_bin_addr)),
                ''.join(binary_address(possible_high_bin_addr)))
            subnets += "The decimal network ID and broadcast address are {}, and {}.\n".format(
                ''.join(network_id),
                ''.join(broadcast_id))
            subnets += "The binary network ID and broadcast address are {}, and {}.\n".format(
                ''.join(binary_address(network_bin_id)),
                ''.join(binary_address(broadcast_bin_id)))

        # last subnet
        network_bin_id = calculate_network_bin_id(bin_ip, 2 ** bits_length - 1, subnet_bits, bits_length,
                                                  final_host_bits)
        network_id = convert_to_decimal(network_bin_id)
        broadcast_bin_id = calculate_broadcast_bin_address(bin_ip, 2 ** bits_length - 1, subnet_bits, bits_length, final_host_bits)
        broadcast_id = convert_to_decimal(broadcast_bin_id)
        possible_low_bin_addr = str((int(network_bin_id) + 1))
        possible_high_bin_addr = str((int(broadcast_bin_id) - 1))
        possible_low_addr = convert_to_decimal(possible_low_bin_addr)
        possible_high_addr = convert_to_decimal(possible_high_bin_addr)
        subnets += "\nThe last network ID is {}, \nIn binary, {}.\n".format(''.join(network_id),
                                                                            ''.join(binary_address(network_bin_id)))
        subnets += "The decimal range is from " + str(network_id) + " to " + str(broadcast_id) + "\n"
        subnets += "The binary range is from " + str(binary_address(network_bin_id)) + " to " \
                   + str(binary_address(broadcast_bin_id)) + "\n"
        subnets += "The decimal range of usable address is from " + str(possible_low_addr) + " to " \
                   + str(possible_high_addr) + "\n"
        subnets += "The binary range is of usable address from " + str(binary_address(possible_low_bin_addr)) + " to " \
                   + str(binary_address(possible_high_bin_addr)) + "\n"
        subnets += "The decimal possible low and high router address are {}, and {}.\n".format(
            ''.join(possible_low_addr),
            ''.join(possible_high_addr))
        subnets += "The binary possible low and high router address are {}, and {}.\n".format(
            ''.join(binary_address(possible_low_bin_addr)),
            ''.join(binary_address(possible_high_bin_addr)))
        subnets += "The decimal network ID and broadcast address are {}, and {}.\n".format(
            ''.join(network_id),
            ''.join(broadcast_id))
        subnets += "The binary network ID and broadcast address are {}, and {}.\n".format(
            ''.join(binary_address(network_bin_id)),
            ''.join(binary_address(broadcast_bin_id)))
    return subnets


def main():
    input_ip = input("Please enter an ip address: ")
    input_ip = input_ip.split(".")
    input_number_of_subnets = input("Please enter a number of subnets: ")
    input_number_of_subnets = int(input_number_of_subnets)
    # check the ip address
    check_ip_address(input_ip)
    # calculate the subnet mask
    mask = mask_for_ip(input_ip)
    mask = mask.split(".")
    # get the binary subnet mask
    bin_mask = convert_to_binary(mask)
    # check the number of subnets
    check_number_of_subnets(bin_mask, input_number_of_subnets)
    print("Current network: " + str(current_network(input_ip, mask)))
    # the current network without dots
    no_dot_network = current_network(input_ip, mask).split('.')
    print("Current mask: " + str(current_mask(mask)))
    ones = bin_mask.count("1")
    # calculate the broadcast address
    fixed = convert_to_binary(no_dot_network)[:ones]
    changed = convert_to_binary(no_dot_network)[ones:].replace("0", "1")
    broadcast_address = fixed + changed
    print("The range is from " + str(current_network(input_ip, mask)) + " to " + convert_to_decimal(broadcast_address))
    # calculate possible low and high router address
    possible_low = str(int(convert_to_binary(no_dot_network)) + 1)
    possible_high = str(int(broadcast_address) - 1)
    print("The possible low router address is: "+ convert_to_decimal(possible_low) +
          "\nThe possible high router address is: " + convert_to_decimal(possible_high) + "\n")
    print(requested_n_subnets(input_number_of_subnets, input_ip, mask, 5))


if __name__ == "__main__":
    main()
