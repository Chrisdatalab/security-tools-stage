def display_result(open_port):
    print("PORT\tSTATUS\tSERVICE")
    for port, info in open_port.items():
        if info["status"] == "open"and info["service"] != "unknown":
            print(f"{port:<8}{info['status']:<10}{info['service']}")