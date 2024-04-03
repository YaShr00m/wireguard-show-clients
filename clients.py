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
def calculate_minutes_ago(last_handshake_time):
    current_time = int(time.time())
    time_difference = current_time - last_handshake_time
    return round(time_difference / 60)

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
        online_clients = {name: info for name, info in clients_info.items() if int(info['received_bytes']) != 0 or int(info['sent_bytes']) != 0}
        offline_clients = {name: info for name, info in clients_info.items() if name not in online_clients or (name in clients_handshake_times and clients_handshake_times[name] == 0)}

        # Удаляем из списка онлайн клиентов тех, у которых последний handshake был более 5 минут назад
        for client_name, handshake_time in clients_handshake_times.items():
            if client_name in online_clients and calculate_minutes_ago(handshake_time) > 5:
                offline_clients[client_name] = online_clients.pop(client_name)

        # Сортируем клиентов по общему объему трафика
        sorted_online_clients = sorted(online_clients.items(), key=lambda x: int(x[1]['received_bytes']) + int(x[1]['sent_bytes']), reverse=True)

        # Выводим информацию об онлайн клиентах
        for client_name, info in sorted_online_clients:
            last_handshake_text = "N/A"
            if client_name in clients_handshake_times and clients_handshake_times[client_name] != 0:
                last_handshake_time = clients_handshake_times[client_name]
                minutes_ago = calculate_minutes_ago(last_handshake_time)
                last_handshake_text = f"{minutes_ago} мин. назад"
            stdscr.addstr(f"{client_name + ':':<20}", curses.color_pair(1))
            stdscr.addstr(f"RX: {bytes_to_megabytes(info['sent_bytes']):<10} , TX: {bytes_to_megabytes(info['received_bytes']):<10} {last_handshake_text}\n")

        # Выводим информацию об оффлайн клиентах
        if offline_clients:
            stdscr.addstr("\nOffline:\n\n", curses.color_pair(2))
            for client_name in offline_clients:
                if client_name in clients_handshake_times and clients_handshake_times[client_name] != 0:
                    minutes_ago = calculate_minutes_ago(clients_handshake_times[client_name])
                    stdscr.addstr(f"{client_name} (был {minutes_ago} мин. назад)\n")
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
