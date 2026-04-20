from ping3 import ping


from ping3 import ping


def check_packet_loss(ip):

    success = 0

    for i in range(3):  # 🔥 بدل 10
        r = ping(ip, timeout=1)

        if r is not None:
            success += 1

    loss = 3 - success

    return loss