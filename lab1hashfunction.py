def calculate_checksum(iin: str) -> int:
    """
    Функция вычисления контрольного разряда ИИН (Модуль 11).
    :param iin: строка из 11 цифр (без контрольного разряда)
    :return: контрольный разряд (0-9)
    """
    digits = [int(d) for d in iin]

    # --- Первый проход ---
    weights = list(range(1, 12))  # веса от 1 до 11
    s = sum(d * w for d, w in zip(digits, weights))
    k = s % 11
    if k < 10:
        return k

    # --- Второй проход ---
    weights2 = list(range(3, 12)) + [1, 2]  # смещение весов
    s2 = sum(d * w for d, w in zip(digits, weights2))
    k2 = s2 % 11
    return k2 if k2 < 10 else 0  # если снова >=10, то контрольный разряд = 0


if __name__ == "__main__":
    # Примеры проверки
    iin1 = "02010351234"  # пример из задания
    iin2 = "85080831073"  # пример для второго прохода

    print(f"IIN: {iin1}, контрольный разряд = {calculate_checksum(iin1)}")
    print(f"IIN: {iin2}, контрольный разряд = {calculate_checksum(iin2)}")

