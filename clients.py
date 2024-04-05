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

# Функция для определения времени, прошедшего с момента handshake в минутах
def calculate_time_ago(last_handshake_time):
    current_time = int(time.time())
    time_difference = current_time - last_handshake_time
    minutes = time_difference // 60
    hours = minutes // 60
    days = hours // 24
    return days, hours % 24, minutes % 60  # Возвращаем кортеж из дней, часов и минут

# Инициализация окна curses
stdscr = curses.initscr()
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
        stdscr.clear()

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

        # Разделяем клиентов на онлайн и оффлайн
        online_clients = {}
        offline_clients = {}

        # Обходим всех клиентов и определяем их статус
        for client_name, handshake_time in clients_handshake_times.items():
            days, _, minutes = calculate_time_ago(handshake_time)
            if days == 0 and minutes <= 5:  # Если последний handshake был в пределах 5 минут, считаем клиента онлайн
                online_clients[client_name] = clients_info[client_name]
            else:
                offline_clients[client_name] = clients_info[client_name]

        # Сортируем онлайн клиентов по общему объему трафика
        sorted_online_clients = sorted(online_clients.items(), key=lambda x: int(x[1]['received_bytes']) + int(x[1]['sent_bytes']), reverse=True)

        # Выводим информацию об онлайн клиентах
        for client_name, info in sorted_online_clients:
            last_handshake_text = "N/A"
            if client_name in clients_handshake_times and clients_handshake_times[client_name] != 0:
                last_handshake_time = clients_handshake_times[client_name]
                days, hours, minutes = calculate_time_ago(last_handshake_time)
                if days > 0:
                    last_handshake_text = f"{days}d {hours}h {minutes}m ago"
                elif hours > 0:
                    last_handshake_text = f"{hours}h {minutes}m ago"
                else:
                    last_handshake_text = f"{minutes}m ago"
            stdscr.addstr(f"{client_name + '':<21}", curses.color_pair(1))
            stdscr.addstr(f"| RX: {bytes_to_megabytes(info['sent_bytes']):<10} |  TX: {bytes_to_megabytes(info['received_bytes']):<10} | {last_handshake_text}\n")

        # Сортируем оффлайн клиентов по времени последнего handshake
        sorted_offline_clients = sorted(offline_clients.items(), key=lambda x: clients_handshake_times[x[0]], reverse=True)

        # Выводим информацию об оффлайн клиентах
        if sorted_offline_clients:
            stdscr.addstr("\nOffline:\n\n", curses.color_pair(2))
            for client_name, info in sorted_offline_clients:
                if client_name in clients_handshake_times and clients_handshake_times[client_name] != 0:
                    days, hours, minutes = calculate_time_ago(clients_handshake_times[client_name])
                    if days > 0:
                        stdscr.addstr(f"{client_name+ '':<21} {days}d {hours}h {minutes}m ago\n")
                    elif hours > 0:
                        stdscr.addstr(f"{client_name+ '':<21} {hours}h {minutes}m ago\n")
                    else:
                        stdscr.addstr(f"{client_name+ '':<21} {minutes}m ago\n")
                else:
                    stdscr.addstr(f"{client_name}\n")

        stdscr.refresh()

        # Ждем 2 секунды перед обновлением информации
        time.sleep(2)

finally:
    # Восстанавливаем настройки терминала перед выходом
    curses.nocbreak()
    stdscr.keypad(False)
    curses.echo()
    curses.endwin()
