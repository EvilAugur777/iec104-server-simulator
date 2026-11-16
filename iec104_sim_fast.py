import os
import socket
import struct
import threading
import time
import random
from datetime import datetime

HOST = '127.0.0.1'
PORT = 2404
CA = 1               # Общий адрес станции
START_IOA = 1        # Начальный адрес тега
TAG_COUNT = 50000    # Количество тегов
BATCH_SIZE = 30      # Сколько тегов паковать в один TCP-кадр
PERIOD_SEC = 0.10     # Строгий период отправки: 0.1 сек = 100 мс (500 000 тегов/сек)

LOG_DIR = '/tmp/iec104_sim_logs'
LOG_FILE = os.path.join(LOG_DIR, 'stats_fast.log')
os.makedirs(LOG_DIR, exist_ok=True)

def write_file_log(text):
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(text + '\n')

def prepare_templates():
    print(f"[*] Предгенерация {TAG_COUNT} тегов в память...")
    all_ioas = list(range(START_IOA, START_IOA + TAG_COUNT))
    templates = []
    
    for i in range(0, TAG_COUNT, BATCH_SIZE):
        batch = all_ioas[i:i + BATCH_SIZE]
        count = len(batch)
        apdu_len = 4 + 6 + count * 8
        
        # Резервируем 6 байт под APCI + заголовок ASDU (6 байт)
        pkt = bytearray(6)
        pkt.extend(struct.pack('<BBBBH', 13, count, 3, 0, CA))
        
        for ioa in batch:
            pkt.extend(ioa.to_bytes(3, 'little'))
            pkt.extend(struct.pack('<fB', random.uniform(10.0, 100.0), 0x00))
            
        templates.append((pkt, apdu_len, count))
    print(f"[*] Готово! Сформировано {len(templates)} шаблонов кадров.")
    return templates

PREBUILT_PACKETS = prepare_templates()

def handle_client(conn, addr):
    print(f"[+] Подключилась SCADA: {addr}")
    print(f"[*] Лог статистики раз в минуту пишется в: {LOG_FILE}")
    
    started = False
    send_seq = 0
    recv_seq = 0
    
    total_frames_sent = 0
    total_frames_acked = 0
    total_tags_sent = 0
    last_ack_seq = 0
    
    frame_tags_map = {}
    total_tags_acked = 0
    lock = threading.Lock()

    def process_ack(ack_num):
        nonlocal last_ack_seq, total_frames_acked, total_tags_acked
        diff = (ack_num - last_ack_seq) % 32768
        if 0 < diff < 16384:
            for step in range(1, diff + 1):
                seq_idx = (last_ack_seq + step - 1) % 32768
                total_tags_acked += frame_tags_map.pop(seq_idx, 0)
            total_frames_acked += diff
            last_ack_seq = ack_num

    def receiver():
        nonlocal started, recv_seq
        try:
            while True:
                header = conn.recv(6)
                if not header or len(header) < 6:
                    break
                ctrl1 = header[2]
                
                if ctrl1 == 0x07:
                    conn.sendall(b'\x68\x04\x0B\x00\x00\x00')
                    started = True
                    print("[*] SCADA активировала передачу данных (STARTDT)")
                elif ctrl1 == 0x43:
                    conn.sendall(b'\x68\x04\x83\x00\x00\x00')
                elif ctrl1 == 0x01:
                    ack_num = struct.unpack('<H', header[4:6])[0] >> 1
                    with lock:
                        process_ack(ack_num)
                elif (ctrl1 & 0x01) == 0:
                    apdu_len = header[1]
                    ack_num = struct.unpack('<H', header[4:6])[0] >> 1
                    if apdu_len > 4:
                        conn.recv(apdu_len - 4)
                    with lock:
                        process_ack(ack_num)
                        recv_seq = (recv_seq + 1) % 32768
                        s_frame = struct.pack('<BBHH', 0x68, 0x04, 0x01, recv_seq << 1)
                        conn.sendall(s_frame)
        except Exception:
            pass

    threading.Thread(target=receiver, daemon=True).start()

    try:
        cycle_num = 0
        next_tick = time.perf_counter()
        last_min_time = time.time()
        last_min_tags_acked = 0

        while True:
            if not started:
                time.sleep(0.05)
                next_tick = time.perf_counter()
                last_min_time = time.time()
                continue
            
            cycle_num += 1
            t_start = time.perf_counter()

            # Обновляем счетчик цикла в самом первом теге первого пакета (смещение 15..19 байт)
            first_pkt = PREBUILT_PACKETS[0][0]
            struct.pack_into('<f', first_pkt, 15, float(cycle_num))

            with lock:
                for pkt, apdu_len, count in PREBUILT_PACKETS:
                    struct.pack_into('<BBHH', pkt, 0, 0x68, apdu_len, send_seq << 1, recv_seq << 1)
                    conn.sendall(pkt)
                    frame_tags_map[send_seq] = count
                    send_seq = (send_seq + 1) % 32768
                    total_frames_sent += 1
                    total_tags_sent += count
            
            send_time = (time.perf_counter() - t_start) * 1000

            if cycle_num % 10 == 0:
                with lock:
                    queue_frames = total_frames_sent - total_frames_acked
                    queue_tags = total_tags_sent - total_tags_acked
                print(
                    f"Цикл #{cycle_num} | Отпр: {send_time:.2f} мс | "
                    f"Подтверждено SCADA: {total_tags_acked} тегов | "
                    f"В очереди SCADA: {queue_tags} тегов ({queue_frames} кадр.)"
                )

            now = time.time()
            if now - last_min_time >= 60.0:
                dt_min = now - last_min_time
                with lock:
                    acked_now = total_tags_acked
                    sent_now = total_tags_sent
                    q_tags = sent_now - acked_now
                
                tags_per_min = acked_now - last_min_tags_acked
                tags_per_sec = int(tags_per_min / dt_min)
                ts_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                log_line = (
                    f"{ts_str} | Подтверждено за мин: {tags_per_min} ({tags_per_sec} тег/сек) | "
                    f"Всего подтверждено: {acked_now} | Всего отправлено: {sent_now} | "
                    f"Очередь в SCADA: {q_tags}"
                )
                write_file_log(log_line)
                
                last_min_time = now
                last_min_tags_acked = acked_now

            next_tick += PERIOD_SEC
            sleep_time = next_tick - time.perf_counter()
            if sleep_time > 0:
                time.sleep(sleep_time)
            else:
                next_tick = time.perf_counter()

    except Exception as e:
        print(f"[-] Клиент отключился: {e}")
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)
print(f"Быстрый имитатор МЭК-104 (такт {int(PERIOD_SEC*1000)} мс) запущен на {HOST}:{PORT}...")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
