import pyshark
import asyncio
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# указываем путь к tshark
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# Создаем event loop
try:
    loop = asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

# Анализируем файл
file_pyt = "dhcp.pcapng"

try:
    # указываем путь к tshark
    cap = pyshark.FileCapture(
        file_pyt,
        tshark_path=TSHARK_PATH,
    )

    packets = []
    dhcp_processes = []

    for packet in cap:
        packet_info = {}

        # Проверяем DHCP
        if hasattr(packet, 'dhcp'):
            packet_info['protocol'] = 'DHCP'

            # Определяем тип процесса Request/Reply
            process_type = 'Unknown'
            if hasattr(packet.dhcp, 'type'):
                type_val = packet.dhcp.type
                if type_val == '1':
                    process_type = 'Request'
                else:
                    process_type = 'Reply'

            packet_info['process_type'] = process_type

            # IP адрес
            if hasattr(packet.dhcp, 'your') and str(packet.dhcp.your) != '0.0.0.0':
                packet_info['client_ip'] = str(packet.dhcp.your)
            elif hasattr(packet.dhcp, 'ip_your'):
                packet_info['client_ip'] = packet.dhcp.ip_your
            else:
                packet_info['client_ip'] = '0.0.0.0'

            # Добавляем информацию об источнике и назначении
            if hasattr(packet, 'ip'):
                packet_info['src_ip'] = packet.ip.src
                packet_info['dst_ip'] = packet.ip.dst

                # Добавляем в список процессов DHCP
                dhcp_processes.append({
                    'process': process_type,
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'client_ip': packet_info['client_ip'],
                    'mac': packet.eth.src if hasattr(packet, 'eth') else 'N/A'
                })

            packets.append(packet_info)

        # Проверяем DNS
        elif hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
            packet_info['protocol'] = 'DNS'
            packet_info['query'] = packet.dns.qry_name

            if hasattr(packet, 'ip'):
                packet_info['src_ip'] = packet.ip.src
                packet_info['dst_ip'] = packet.ip.dst

            packets.append(packet_info)

        # Проверяем HTTP
        elif hasattr(packet, 'http') and hasattr(packet.http, 'request_method'):
            packet_info['protocol'] = 'HTTP'
            packet_info['method'] = packet.http.request_method
            if hasattr(packet, 'ip'):
                packet_info['src_ip'] = packet.ip.src
                packet_info['dst_ip'] = packet.ip.dst
            packets.append(packet_info)

    cap.close()

    # создаем DATAFRAME
    df = pd.DataFrame(packets)

    # вывод результатов
    dhcp_packets = [p for p in packets if p.get('protocol') == 'DHCP']
    dns_packets = [p for p in packets if p.get('protocol') == 'DNS']
    http_packets = [p for p in packets if p.get('protocol') == 'HTTP']

    # DNS ЗАПРОСЫ
    print(f"\nDNS-ЗАПРОСЫ:")
    if dns_packets:
        for p in dns_packets[:20]:
            print(p.get('query', 'N/A'))
    else:
        print("Нет DNS запросов")

    # HTTP ЗАПРОСЫ
    print(f"\nHTTP-ЗАПРОСЫ:")
    if http_packets:
        for p in http_packets[:10]:
            print(p.get('method', 'N/A'))
    else:
        print("Нет HTTP запросов")

    # DHCP СОБЫТИЯ
    print(f"\nDHCP-СОБЫТИЯ:")
    if dhcp_packets:
        for p in dhcp_packets:
            print(f"Process: {p.get('process_type', 'Unknown')}")
            print(f"Client IP: {p.get('client_ip', '0.0.0.0')}")
            print()
    else:
        print("Нет DHCP событий")

    #  ВИЗУАЛИЗАЦИЯ

    # Список IP-адресов
    all_ips = []
    if 'src_ip' in df.columns:
        all_ips.extend(df['src_ip'].dropna().tolist())
    if 'dst_ip' in df.columns:
        all_ips.extend(df['dst_ip'].dropna().tolist())

    unique_ips = set(all_ips)

    # Список доменов
    dns_counter = Counter()
    if dns_packets:
        dns_counter = Counter([p.get('query') for p in dns_packets])

    # распределение процессов Request-Reply
    if dhcp_packets:
        # Настройка стиля
        sns.set_style("whitegrid")
        plt.figure(figsize=(10, 6))

        # Считаем количество Request и Reply
        process_counts = Counter([p.get('process_type', 'Unknown') for p in dhcp_packets])

        # Создаем график
        sns.barplot(x=list(process_counts.keys()), y=list(process_counts.values()))
        plt.title('Распределение DHCP-процессов')
        plt.xlabel('Тип процесса')
        plt.ylabel('Количество')
        plt.xticks(rotation=45)

        # Добавляем значения на столбцы
        for i, (_, v) in enumerate(process_counts.items()):
            plt.text(i, v + 0.1, str(v), ha='center')

        plt.tight_layout()
        plt.savefig('dhcp_processes.png', dpi=300)
        plt.show()

except Exception as e:
    print(f"Ошибка: {e}")
finally:
    if not loop.is_closed():
        loop.close()




















