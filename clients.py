import re
import subprocess
import time
import curses

# Функция для получения информации о трафике и последних handshake из команды "sudo wg show wg0 transfer" и "sudo wg show wg0 latest-handshakes"
def get_traffic_and_handshake_info():
    traffic_result = subprocess.run(['sudo', 'wg', 'show', 'wg0', 'transfer'], capture_output=True, text=True)
    handshake_result = subprocess.run(['sudo', 'wg', 'show', 'wg0', 'latest-handshakes'], capture_output=True, text=True)
    return traffic_result.stdout, handshake_result.stdout

# Преобразование байт в мегабайты и гигабайты
def bytes_to_megabytes(bytes):
    mb = round(int(bytes) / (1024 * 1024), 2)
    if mb >= 1024:
        gb = round(mb / 1024, 2)
        return f"{gb} GB"
    else:
        return f"{mb} MB"

# Функция для определения времени, прошедшего с момента handshake
def calculate_time_ago(last_handshake_time):
    current_time = int(time.time())
    time_difference = current_time - last_handshake_time
    hours = time_difference // 3600
    minutes = (time_difference % 3600) // 60
    seconds = time_difference % 60
    return hours, minutes, seconds  # Возвращаем часы, минуты и секунды

def format_last_handshake(hours, minutes, seconds):
    if hours == 0 and minutes == 0:
        return f"{seconds} sec ago"
    elif hours == 0:
        return f"{minutes}m {seconds}s ago"
    else:
        return f"{hours}h {minutes}m ago"

def main(stdscr):
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)

    # Инициализация цветов
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # зеленый
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)    # красный

    # Считываем содержимое файла конфигурации WireGuard
    with open('/etc/wireguard/wg0.conf', 'r') as file:
        config_data = file.read()

    # Находим строки, начинающиеся с "# BEGIN_PEER"
    peers_start = re.findall(r'# BEGIN_PEER (.+)', config_data)

    try:
        while True:
            stdscr.erase()  # Стереть содержимое экрана

            # Получаем информацию о трафике и последних handshake
            traffic_info, handshake_info = get_traffic_and_handshake_info()

            # Создаем словарь для хранения информации о клиентах
            clients_info = {}

            # Обходим всех клиентов
            for client_name in peers_start:
                # Извлекаем информацию о клиенте
                client_info = re.search(rf'# BEGIN_PEER {re.escape(client_name)}\n(.*?)\n# END_PEER {re.escape(client_name)}', config_data, re.DOTALL)
                if client_info:
                    # Извлекаем публичный ключ клиента
                    public_key_match = re.search(r'PublicKey = (.+)', client_info.group(1))
                    if public_key_match:
                        public_key = public_key_match.group(1)

                    # Ищем трафик для данного клиента по его публичному ключу
                    traffic_match = re.search(rf'{re.escape(public_key)}\s+(\d+)\s+(\d+)', traffic_info)
                    if traffic_match:
                        received_bytes = traffic_match.group(1)
                        sent_bytes = traffic_match.group(2)
                        received_mb = bytes_to_megabytes(received_bytes)
                        sent_mb = bytes_to_megabytes(sent_bytes)

                        # Сохраняем информацию о клиенте
                        clients_info[client_name] = {'public_key': public_key, 'received_bytes': received_bytes, 'sent_bytes': sent_bytes}

            # Создаем словарь для хранения информации о времени последнего handshake для каждого клиента
            clients_handshake_times = {}

            # Обходим всех клиентов
            for client_name in peers_start:
                # Извлекаем информацию о клиенте
                client_info = re.search(rf'# BEGIN_PEER {re.escape(client_name)}\n(.*?)\n# END_PEER {re.escape(client_name)}', config_data, re.DOTALL)
                if client_info:
                    # Извлекаем публичный ключ клиента
                    public_key_match = re.search(r'PublicKey = (.+)', client_info.group(1))
                    if public_key_match:
                        public_key = public_key_match.group(1)

                    # Ищем информацию о последнем handshake для данного клиента по его публичному ключу
                    handshake_match = re.search(rf'{re.escape(public_key)}\s+(.+)', handshake_info)
                    if handshake_match:
                        last_handshake = handshake_match.group(1)

                        # Преобразуем время последнего handshake в формат Unix timestamp
                        last_handshake_time = int(last_handshake)

                        # Сохраняем информацию о времени последнего handshake для клиента
                        clients_handshake_times[client_name] = last_handshake_time

            # Обходим всех клиентов и определяем их статус
            online_clients = {}
            offline_clients = {}
            for client_name, handshake_time in clients_handshake_times.items():
                hours, minutes, seconds = calculate_time_ago(handshake_time)
                if hours > 0 or minutes > 4:
                    offline_clients[client_name] = clients_info[client_name]
                else:
                    online_clients[client_name] = clients_info[client_name]


            # Сортируем онлайн клиентов только по трафику
            sorted_online_clients = sorted(online_clients.items(), key=lambda x: int(x[1]['received_bytes']) + int(x[1]['sent_bytes']), reverse=True)


           # Выводим информацию об онлайн клиентах
            for client_name, info in sorted_online_clients:
                last_handshake_text = ""
                if client_name in clients_handshake_times and clients_handshake_times[client_name] != 0:
                    last_handshake_time = clients_handshake_times[client_name]
                    hours, minutes, seconds = calculate_time_ago(last_handshake_time)
                    last_handshake_text = format_last_handshake(hours, minutes, seconds)
                stdscr.addstr(f"{client_name + '':<21}", curses.color_pair(1))
                stdscr.addstr(f"| RX: {bytes_to_megabytes(info['sent_bytes']):<10} |  TX: {bytes_to_megabytes(info['received_bytes']):<10} | {last_handshake_text}\n")


            # Выводим информацию об оффлайн клиентах
            if offline_clients:
                stdscr.addstr("\nOffline:\n\n", curses.color_pair(2))
                sorted_offline_clients = sorted(offline_clients.items(), key=lambda x: clients_handshake_times[x[0]], reverse=True)
                for client_name, info in sorted_offline_clients:
                    last_handshake_text = ""
                    if client_name in clients_handshake_times and clients_handshake_times[client_name] != 0:
                        last_handshake_time = clients_handshake_times[client_name]
                        hours, minutes, seconds = calculate_time_ago(last_handshake_time)
                        last_handshake_text = format_last_handshake(hours, minutes, seconds)
                    stdscr.addstr(f"{client_name + '':<21} {last_handshake_text}\n")

            stdscr.refresh()  # Обновить экран

            # Ждем 1 сек перед обновлением информации
            time.sleep(1)

    finally:
        # Восстанавливаем настройки терминала перед выходом
        curses.nocbreak()
        stdscr.keypad(False)
        curses.echo()
        curses.endwin()

curses.wrapper(main)
