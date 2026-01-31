
import hashlib          # thư viện hỗ trợ các thuật toán hash (MD5, SHA1, SHA256,...)
import itertools        # hỗ trợ sinh ra các tổ hợp/kết hợp ký tự → dùng cho brute force

# Hàm hash mật khẩu
def hash_password(password: str, algo: str = "md5") -> str:
    """
    Nhận vào mật khẩu dạng chuỗi và tên thuật toán (md5, sha1, sha256).
    Trả về hash dạng hex string.
    """
    algo = algo.lower()  # chuẩn hóa tên thuật toán về chữ thường
    if algo == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError("Thuật toán chưa hỗ trợ")  # báo lỗi nếu nhập thuật toán chưa có

# Dictionary attack (in quá trình)

def dictionary_attack_verbose(target_hash, wordlist, algo="md5"):
    """
    Dictionary attack có in log từng từ được thử.
    """
    attempt_count = 0
    for word in wordlist:                       
        attempt_count += 1
        candidate = word.strip()  # bỏ xuống dòng/thừa khoảng trắng
        candidate_hash = hash_password(candidate, algo)

        # In quá trình (chỉ in tối đa 20 lần đầu cho dễ nhìn)
        if attempt_count <= 20:
            print(f"Thử {attempt_count}: '{candidate}' → Hash = {candidate_hash}")

        if candidate_hash == target_hash:  
            print(f"\n[✔] Tìm thấy sau {attempt_count} lần thử!")
            return candidate
    return None


def load_wordlist_from_file(filename):
    """
    Đọc wordlist từ file password.txt
    Mỗi dòng là 1 mật khẩu.
    """
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return f.readlines()  # trả về list các dòng
    except FileNotFoundError:
        print(f"[!] Không tìm thấy file {filename}")
        return []

# Brute force attack 
def brute_force_attack_verbose(target_hash, max_length=4, algo="md5"):
 
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    attempt_count = 0  # đếm số lần thử

    for length in range(1, max_length + 1):            
        for guess in itertools.product(chars, repeat=length):  
            guess = "".join(guess)
            attempt_count += 1
            guess_hash = hash_password(guess, algo)

            # In quá trình (thử tối đa 30 lần đầu để không quá dài)
            if attempt_count <= 30:
                print(f"Thử {attempt_count}: '{guess}' → Hash = {guess_hash}")

            if guess_hash == target_hash:
                print(f"\n[✔] Tìm thấy sau {attempt_count} lần thử!")
                return guess
    print(f"\n[!] Đã thử {attempt_count} khả năng nhưng không tìm thấy.")
    return None


# demo main
if __name__ == "__main__":
    password = input("Nhập mật khẩu gốc để demo: ").strip()

    print("\nChọn thuật toán hash:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA256")

    choice = input("Lựa chọn (1/2/3): ").strip()
    algo_map = {"1": "md5", "2": "sha1", "3": "sha256"}
    algo = algo_map.get(choice, "md5")

    # target_hash = hash_password(password, algo)
    # algo = "md5"
    hashed = hash_password(password, algo)

    print(f"\n[+] Mật khẩu gốc: {password}")
    print(f"[+] Hash ({algo.upper()}): {hashed}")

    # ============= Dictionary attack (dùng wordlist từ file)
    print("\n[Dictionary Attack - từ file password.txt]")
    file_wordlist = load_wordlist_from_file("password.txt")
    if file_wordlist:
        result = dictionary_attack_verbose(hashed, file_wordlist, algo)
        print("Kết quả:", result if result else "Không tìm thấy")

    # ============= Brute force attack (demo mật khẩu ngắn)
    print("\n[Brute Force Attack]")
    result = brute_force_attack_verbose(hashed, max_length=6, algo=algo)
    print("Kết quả:", result if result else "Không crack được")

