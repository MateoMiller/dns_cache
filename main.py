import pickle
import threading
import time
from collections import defaultdict

import dnslib
import socket

from records.aRecord import ARecord
from records.aaaaRecord import AAAARecord
from records.nsRecord import NSRecord
from records.ptrRecord import PTRRecord
from records.record import Record
from records.recordsContainer import RecordsContainer

DNS_PORT = 53
HOST = "127.0.0.1"
REMOTE_DNS_SERVER = "87.224.197.1"
IS_FINISHED = False
LOCK = threading.Lock()

cache = defaultdict(RecordsContainer)


def start_server():
    # Инициализируем два сокета, один для общения с клиентом, другой для общения со сторонним сервером

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_sock:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as remote_server_socket:
            server_sock.bind((HOST, DNS_PORT))
            remote_server_socket.connect((REMOTE_DNS_SERVER, DNS_PORT))
            server_sock.settimeout(1.0)
            remote_server_socket.settimeout(1.0)
            while not IS_FINISHED:
                try:
                    # Получаем запросы от пользователя

                    query_data, customer_addr = server_sock.recvfrom(10000)
                    parser_query = dnslib.DNSRecord.parse(query_data)
                    with LOCK:
                        # Ищем информацию в кэше по ip/имени из запроса
                        cache_records = cache.get(parser_query.q.qname.label)

                        # Если есть какая-то информация по ip/имени, то анализируем её
                        if cache_records is not None:

                            # Удаляем старые записи на случай, если поток, ответсвенный за удаление в данным момент спит
                            cache_records.delete_expired_records()

                            required_info = get_required_info(cache_records, parser_query)

                            # Если на интересующий вопрос уже есть информация, то воспользуемся ею
                            if required_info is not None:
                                print('Взял из кэша')

                                # Добавляем информацию к отправленному нам запросу
                                add_answer_to_query(required_info, parser_query)

                                # Посылаем клиенту его запрос вместе с ответом
                                server_sock.sendto(parser_query.pack(), customer_addr)
                                continue

                        print('Обратился к стороннему серверу')

                        # Если в кэше нет нужной информации, то запросим её у другого сервера
                        remote_server_socket.send(query_data)
                        respond_data, _ = remote_server_socket.recvfrom(10000)

                        # Пересылаем полученный ответ клиенту
                        server_sock.sendto(respond_data, customer_addr)

                        parsed_respond = dnslib.DNSRecord.parse(respond_data)

                        # Обновляем данные в кэше
                        update_cache_records(parsed_respond)

                except socket.timeout:
                    pass
                except Exception as e:
                    print(e)


def add_answer_to_query(required_data, query):
    qtype = query.q.qtype
    q = query.q

    # Для каждого типа запроса добавляем интересующий ответ
    if qtype == dnslib.QTYPE.A:
        # Добавляем все A адреса
        for addr in required_data.addresses:
            query.add_answer(dnslib.RR(
                rname=q.qname, rclass=q.qclass, rtype=q.qtype, ttl=required_data.remain_ttl(),
                rdata=dnslib.A(addr)
            ))
    if qtype == dnslib.QTYPE.AAAA:
        # Добавляем все AAAA адреса
        for addr in required_data.addresses:
            query.add_answer(dnslib.RR(
                rname=q.qname, rclass=q.qclass, rtype=q.qtype, ttl=required_data.remain_ttl(),
                rdata=dnslib.AAAA(addr)
            ))
    if qtype == dnslib.QTYPE.NS:
        # Добавляем все NS серверы
        for addr in required_data.servers:
            query.add_answer(dnslib.RR(
                rname=q.qname, rclass=q.qclass, rtype=q.qtype, ttl=required_data.remain_ttl(),
                rdata=dnslib.NS(addr)
            ))
    if qtype == dnslib.QTYPE.PTR:
        # Добавляем PTR
        query.add_answer(dnslib.RR(
            rname=q.qname, rclass=q.qclass, rtype=q.qtype, ttl=required_data.remain_ttl(),
            rdata=dnslib.PTR(required_data.name))
        )


def get_required_info(cache_records, query) -> Record:
    # Берем информацию по типу запроса
    qtype = query.q.qtype
    if qtype == dnslib.QTYPE.A:
        return cache_records.a
    elif qtype == dnslib.QTYPE.AAAA:
        return cache_records.aaaa
    elif qtype == dnslib.QTYPE.NS:
        return cache_records.ns
    elif qtype == dnslib.QTYPE.PTR:
        return cache_records.ptr


def get_cache_record(query):
    qname = query.q.qname.label
    if qname in cache:
        return cache[qname]


def update_cache_records(dns_answer):
    # Пробегаем по секции ответов и additional

    for new_record in dns_answer.rr + dns_answer.ar:
        record_type = new_record.rtype
        name = new_record.rname.label
        # Берем старую кэш запись, будем её изменять
        cache_records = cache[name]
        if record_type == dnslib.QTYPE.NS:
            update_ns(new_record, cache_records)
        elif record_type == dnslib.QTYPE.A:
            update_a(new_record, cache_records)
        elif record_type == dnslib.QTYPE.AAAA:
            update_aaaa(new_record, cache_records)
        elif record_type == dnslib.QTYPE.PTR:
            update_ptr(new_record, cache_records)


def update_ns(new_record, cached_records):
    # Добавляем NS серверы к кэшу
    if cached_records.ns is None:
        cached_records.ns = NSRecord(new_record.ttl)
    cached_records.ns.servers.append(new_record.rdata.label.label)


def update_a(new_record, cached_records):
    # Добавляем IPV4 адреса в кэшу
    if cached_records.a is None:
        cached_records.a = ARecord(new_record.ttl)
    cached_records.a.addresses.append(new_record.rdata.data)


def update_aaaa(new_record, cached_records):
    # Добавляем IPV6 адреса в кэшу
    if cached_records.aaaa is None:
        cached_records.aaaa = AAAARecord(new_record.ttl)
    cached_records.aaaa.addresses.append(new_record.rdata.data)


def update_ptr(new_record, cached_records):
    # Добавляем PTR запись в кэш
    if cached_records.ptr is None:
        cached_records.ptr = PTRRecord(new_record.ttl, new_record.rdata.label.label)


def cache_clear_loop():
    # Каждые 10 секунд просматриваем кэш и удаляем устаревшие данные
    while not IS_FINISHED:
        time.sleep(10)
        with LOCK:
            expired_records_keys = []
            for key in cache:
                records = cache[key]
                records.delete_expired_records()
                if records.is_empty():
                    expired_records_keys.append(key)
            for key in expired_records_keys:
                cache.pop(key)


def input_handler_loop():
    # Считываем input пока не увидим exit, чтобы выключить сервер
    global IS_FINISHED
    while not IS_FINISHED:
        inp = input()
        if inp == 'exit':
            IS_FINISHED = True
            print('Подождите, программа завершает свою работу')
        else:
            print('Введите exit, чтобы завершить работу сервера')


if __name__ == '__main__':
    # Берем сохраненный кэш
    try:
        with open('backup.file', 'rb') as file:
            old_cache = pickle.loads(file.read())
            cache = old_cache
    except Exception:
        pass
    threading.Thread(target=cache_clear_loop).start()
    threading.Thread(target=input_handler_loop).start()
    try:
        start_server()
    except OSError as e:
        print(f'{HOST}/{DNS_PORT} Уже занят')
    except socket.error as e:
        print(f'Не удалось подключиться к {REMOTE_DNS_SERVER}/{DNS_PORT}')

    # Сохраняем новый кэш
    try:
        with open('backup.file', 'wb') as file:
            file.write(pickle.dumps(cache))
    except Exception as e:
        print(e)
