import zlib
import numpy as np
import struct

def parse_itxt_chunk_data(chunk_data):
    """
    Parsuje dane chunku iTXt.
    Zwraca słownik z sparsowanymi danymi.
    """
    offset = 0
    
    try:
        keyword_end = chunk_data.find(b'\x00', offset)
        if keyword_end == -1:
            raise ValueError("Brak zakończenia Keyword")
        keyword = chunk_data[offset:keyword_end].decode('latin-1')
        offset = keyword_end + 1
    except UnicodeDecodeError:
        keyword = "[BŁĄD DEKODOWANIA KEYWORD]"

    # 2. Compression Flag
    if offset >= len(chunk_data):
        raise ValueError("Brak Compression Flag w danych iTXt")
    compression_flag = chunk_data[offset]
    offset += 1

    # 3. Compression Method
    if offset >= len(chunk_data):
        raise ValueError("Brak Compression Method w danych iTXt")
    compression_method = chunk_data[offset]
    offset += 1

    # 4. Language Tag (zakończony null)
    try:
        lang_tag_end = chunk_data.find(b'\x00', offset)
        if lang_tag_end == -1:
            raise ValueError("Brak zakończenia Language Tag w danych iTXt")
        lang_tag = chunk_data[offset:lang_tag_end].decode('latin-1')
        offset = lang_tag_end + 1
    except UnicodeDecodeError:
        lang_tag = "[BŁĄD DEKODOWANIA LANGUAGE TAG]"

    # 5. Translated Keyword (zakończony null)
    try:
        translated_keyword_end = chunk_data.find(b'\x00', offset)
        if translated_keyword_end == -1:
            raise ValueError("Brak zakończenia Translated Keyword w danych iTXt")
        translated_keyword = chunk_data[offset:translated_keyword_end].decode('latin-1')
        offset = translated_keyword_end + 1
    except UnicodeDecodeError:
        translated_keyword = "[BŁĄD DEKODOWANIA TRANSLATED KEYWORD]"

    # 6. Text (opcjonalnie skompresowany)
    text_data = chunk_data[offset:]

    decoded_text = ""
    if compression_flag == 1:
        if compression_method == 0:  # deflate
            try:
                decoded_text = zlib.decompress(text_data).decode('latin-1')
            except zlib.error as e:
                decoded_text = f"[Błąd dekompresji tekstu: {e}]"
            except UnicodeDecodeError:
                decoded_text = "[Błąd dekodowania zdekompresowanego tekstu]"
        else:
            decoded_text = f"[Skompresowany tekst - nieznana metoda kompresji: {compression_method}]"
    else:
        try:
            decoded_text = text_data.decode('latin-1')
        except UnicodeDecodeError:
            decoded_text = "[Błąd dekodowania nieskompresowanego tekstu]"

    return {
        'keyword': keyword,
        'compression_flag': compression_flag,
        'compression_method': compression_method,
        'language_tag': lang_tag,
        'translated_keyword': translated_keyword,
        'text': decoded_text
    }
    
def generate_palette_image_numpy(palette_data, width=32):
    """Generuje tablicę NumPy reprezentującą obraz z danych palety."""
    # RGB - dzielenie aby uzyskać ilość kolorów
    num_entries = len(palette_data) // 3
    
    height = (num_entries + width - 1) // width 

    # Wyjściowa tablica 
    img_array = np.zeros((height, width, 3), dtype=np.uint8)

    for i in range(num_entries):
        x = i % width
        y = i // width
        r = palette_data[i * 3]
        g = palette_data[i * 3 + 1]
        b = palette_data[i * 3 + 2]
        img_array[y, x] = [r, g, b]
    return img_array

def parse_ihdr_chunk(ihdr_data):
    """
    Zwracanie słownika z informacjami z IHDR
    """
    if len(ihdr_data) != 13:
        raise ValueError("IHDR chunk data has incorrect length (expected 13 bytes)")

    width, height, bit_depth, color_type, compression_method, filter_method, interlace_method = struct.unpack('>IIBBBBB', ihdr_data)
    
    return {
        'width': width,
        'height': height,
        'bit_depth': bit_depth,
        'color_type': color_type,
        'compression_method': compression_method,
        'filter_method': filter_method,
        'interlace_method': interlace_method
    }