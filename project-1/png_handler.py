import struct
import zlib
import matplotlib.pyplot as plt
from utils import parse_itxt_chunk_data,  generate_palette_image_numpy, parse_ihdr_chunk

def _read_chunk(file):
    """Odczytuje pojedynczy chunk z pliku PNG."""
    try:
        length_bytes = file.read(4)
        if not length_bytes:
            return None
        length = struct.unpack('>I', length_bytes)[0]

        type_bytes = file.read(4)
        chunk_type = type_bytes.decode('ascii')

        data = file.read(length)
        crc = file.read(4)

        return {'length': length, 'type': chunk_type, 'data': data, 'crc': crc}
    except (struct.error, IndexError):
        return None

def read_png_file(file_path):
    """Odczytuje plik PNG, sprawdza sygnaturę i zwraca listę chunków."""
    with open(file_path, 'rb') as f:
        if f.read(8) != b'\x89PNG\r\n\x1a\n':
            raise ValueError("To nie jest prawidłowy plik PNG")

        print("=== Sygnatura PNG poprawna ===")
        chunks = []
        while True:
            chunk = _read_chunk(f)
            if chunk is None or chunk['type'] == 'IEND':
                if chunk:
                    chunks.append(chunk)
                break
            chunks.append(chunk)
    return chunks

def print_critical_chunks_info(chunks, additional_info=False):
    """Przetwarza i wyświetla informacje z krytycznych chunków."""
    print("\n=== Informacje z krytycznych chunków ===")
    palette_numpy_array = None
    for chunk in chunks:
        if chunk['type'] == 'IHDR':
            ihdr_info = parse_ihdr_chunk(chunk['data'])
            
            print("\n[IHDR - Nagłówek obrazu]")
            print(f"Szerokość: {ihdr_info['width']} pikseli")
            print(f"Wysokość: {ihdr_info['height']} pikseli")
            print(f"Głębia bitowa: {ihdr_info['bit_depth']} bitów")
            color_types = {0: 'Skala szarości', 2: 'Kolor RGB', 3: 'Paletowy', 4: 'Skala szarości + alfa', 6: 'Kolor RGB + alfa'}
            print(f"Typ koloru: {color_types.get(ihdr_info['color_type'], 'Nieznany')}")
            print(f"Metoda kompresji: {'Deflate/Inflate' if ihdr_info['compression_method'] == 0 else 'Nieznana'}")
            print(f"Metoda filtrowania: {'Adaptive filtering' if ihdr_info['filter_method'] == 0 else 'Nieznana'}")
            interlace_methods = {0: 'Brak przeplotu', 1: 'Adam7'}
            print(f"Metoda przeplotu: {interlace_methods.get(ihdr_info['interlace_method'], 'Nieznana')}")
            
        elif chunk['type'] == 'PLTE':
            print("\n[PLTE - Paleta kolorów]")
            palette_data = chunk['data']
            num_entries = len(palette_data) // 3
            print(f"Liczba wpisów w palecie: {num_entries}")
            
            for i in range(num_entries):
                r = palette_data[i * 3]
                g = palette_data[i * 3 + 1]
                b = palette_data[i * 3 + 2]
                print(f"  Indeks {i:03d}: RGB({r:3d}, {g:3d}, {b:3d}) | HEX: #{r:02X}{g:02X}{b:02X}")

            # Tablica palety do wygenerowania obrazu
            palette_numpy_array = generate_palette_image_numpy(palette_data)

        elif chunk['type'] == 'IDAT':
            print(f"\n[IDAT] - Rozmiar skompresowanych danych: {chunk['length']} bajtów")
            if additional_info:
                print(f"  Pełne dane IDAT (reprezentacja bajtowa): {chunk['data']}")
                print(f"  CRC: {chunk['crc'].hex()}")

        elif chunk['type'] == 'IEND':
            print("\n[IEND - Koniec obrazu]")
            if additional_info:
                print(f"  Surowe dane IEND: {chunk['data']}")
                print(f"  CRC: {chunk['crc'].hex()}")

    if palette_numpy_array is not None:
        plt.imsave("palette.png", palette_numpy_array)
        print("\nObraz palety zapisano do pliku palette.png")
    
    return ihdr_info


def print_ancillary_chunks_info(chunks, color_type, bit_depth):
    """Przetwarza i wyświetla informacje z wybranych dodatkowych chunków."""
    print("\n=== Informacje z dodatkowych chunków (Ancillary Chunks) ===")
    found_ancillary = False
    for chunk in chunks:
        if chunk['type'] == 'tEXt':
            found_ancillary = True
            try:
                # Przykładowy chunk: tEXtAuthor\x00PDF Tools
                # null_byte_index znajduje pierwszy bajt null, który oddziela słowo kluczowe od tekstu
                null_byte_index = chunk['data'].find(b'\x00')
                if null_byte_index != -1:
                    keyword = chunk['data'][:null_byte_index].decode('latin-1')
                    text = chunk['data'][null_byte_index + 1:].decode('latin-1')
                    print(f"\n[tEXt - Dane tekstowe]")
                    print(f"  Słowo kluczowe: {keyword}")
                    print(f"{text}")
                else:
                    print(f"\n[tEXt - Dane tekstowe] (Nieprawidłowy format - brak separatora null)")
            except Exception as e:
                print(f"\n[tEXt - Dane tekstowe] (Błąd dekodowania: {e})")

        elif chunk['type'] == 'zTXt':
            found_ancillary = True
            try:
                # Ten sam przypadek jak w tEXt
                # Zkompresowany tekst zamiast normalnego tekstu
                null_byte_index = chunk['data'].find(b'\x00')
                if null_byte_index != -1:
                    keyword = chunk['data'][:null_byte_index].decode('latin-1')
                    compression_method = chunk['data'][null_byte_index + 1]
                    compressed_text = chunk['data'][null_byte_index + 2:]
                    decompressed_text = zlib.decompress(compressed_text).decode('latin-1')
                    print(f"\n[zTXt - Skompresowane dane tekstowe]")
                    print(f"  Słowo kluczowe: {keyword}")
                    print(f"  Metoda kompresji: {'Deflate' if compression_method == 0 else 'Nieznana'}")
                    print(f"  Tekst: {decompressed_text}")
                else:
                    print(f"\n[zTXt - Skompresowane dane tekstowe] (Nieprawidłowy format - brak separatora null)")
            except Exception as e:
                print(f"\n[zTXt - Skompresowane dane tekstowe] (Błąd dekodowania/dekompresji: {e})")

        elif chunk['type'] == 'iTXt':
            found_ancillary = True
            try:
                parsed_itxt = parse_itxt_chunk_data(chunk['data'])
                
                print(f"\n[iTXt - Internacjonalizowane dane tekstowe]")
                print(f"  Słowo kluczowe: {parsed_itxt['keyword']}")
                print(f"  Flaga kompresji: {parsed_itxt['compression_flag']} ({'Skompresowany' if parsed_itxt['compression_flag'] == 1 else 'Nieskompresowany'})")
                print(f"  Metoda kompresji: {parsed_itxt['compression_method']} ({'Deflate' if parsed_itxt['compression_method'] == 0 else 'Brak/Nieznana'})")
                print(f"  Tag języka: {parsed_itxt['language_tag']}")
                print(f"  Przetłumaczone słowo kluczowe: {parsed_itxt['translated_keyword']}")
                print(f"  Tekst: {parsed_itxt['text'][:200]}{'...' if len(parsed_itxt['text']) > 200 else ''}")
            except Exception as e:
                print(f"\n[iTXt - Internacjonalizowane dane tekstowe] (Błąd dekodowania/dekompresji: {e})")

        elif chunk['type'] == 'gAMA':
            found_ancillary = True
            try:
                gamma_int = struct.unpack('>I', chunk['data'])[0]
                gamma = gamma_int / 100000.0
                print(f"\n[gAMA - Wartość gamma]")
                print(f"  Gamma: {gamma:.4f}")
            except Exception as e:
                print(f"\n[gAMA - Wartość gamma] (Błąd dekodowania: {e})")

        elif chunk['type'] == 'cHRM':
            found_ancillary = True
            try:
                white_point_x, white_point_y, red_x, red_y, green_x, green_y, blue_x, blue_y = \
                    struct.unpack('>IIIIIIII', chunk['data'])
                print(f"\n[cHRM - Chromatyczność]")
                print(f"  Punkt bieli (x, y): ({white_point_x / 100000.0:.5f}, {white_point_y / 100000.0:.5f})")
                print(f"  Czerwony (x, y): ({red_x / 100000.0:.5f}, {red_y / 100000.0:.5f})")
                print(f"  Zielony (x, y): ({green_x / 100000.0:.5f}, {green_y / 100000.0:.5f})")
                print(f"  Niebieski (x, y): ({blue_x / 100000.0:.5f}, {blue_y / 100000.0:.5f})")
            except Exception as e:
                print(f"\n[cHRM - Chromatyczność] (Błąd dekodowania: {e})")

        elif chunk['type'] == 'sRGB':
            found_ancillary = True
            try:
                rendering_intent = chunk['data'][0]
                intents = {0: 'Perceptual', 1: 'Relative colorimetric', 2: 'Saturation', 3: 'Absolute colorimetric'}
                print(f"\n[sRGB - Standardowy profil kolorów RGB]")
                print(f"  Intent renderowania: {intents.get(rendering_intent, 'Nieznany')}")
            except Exception as e:
                print(f"\n[sRGB - Standardowy profil kolorów RGB] (Błąd dekodowania: {e})")

        elif chunk['type'] == 'bKGD':
            found_ancillary = True
            print(f"\n[bKGD - Kolor tła]")
            if color_type == None or bit_depth == None:
               print(f"  (Brak informacji o kolorze lub głębi bitowej)")
            else:
                try:
                    if color_type == 0:  # Skala szarości
                        gray_value = struct.unpack('>H', chunk['data'])[0]
                        print(f"  Wartość szarości: {gray_value}")
                    elif color_type == 2:  # RGB
                        r, g, b = struct.unpack('>BBB', chunk['data'][:3])
                        print(f"  Kolor RGB: ({r}, {g}, {b})")
                    elif color_type == 3:  # Paleta
                        palette_index = chunk['data'][0]
                        print(f"  Indeks palety: {palette_index}")
                    elif color_type == 4:  # Skala szarości + alfa
                        gray_value, alpha_value = struct.unpack('>HB', chunk['data'])
                        print(f"  Wartość szarości: {gray_value}, Wartość alfa: {alpha_value}")
                    elif color_type == 6:  # RGB + alfa
                        r, g, b, alpha = struct.unpack('>BBBB', chunk['data'][:4])
                        print(f"  Kolor RGBA: ({r}, {g}, {b}, {alpha})")
                except Exception as e:
                    print(f"  Błąd dekodowania koloru tła: {e}")


        elif chunk['type'] == 'pHYs':
            found_ancillary = True
            try:
                pixels_per_unit_x, pixels_per_unit_y, unit_specifier = struct.unpack('>IIB', chunk['data'])
                units = {0: 'Brak jednostek (nieznane)', 1: 'Metr'}
                print(f"\n[pHYs - Fizyczne wymiary piksela]")
                print(f"  Piksele na jednostkę X: {pixels_per_unit_x}")
                print(f"  Piksele na jednostkę Y: {pixels_per_unit_y}")
                print(f"  Jednostka: {units.get(unit_specifier, 'Nieznana')}")
            except Exception as e:
                print(f"\n[pHYs - Fizyczne wymiary piksela] (Błąd dekodowania: {e})")



    if not found_ancillary:
        print("Brak wykrytych dodatkowych chunków.")


def anonymize_png(chunks, output_path):
    """Anonimizuje PNG: usuwa niekrytyczne chunki i scala IDATy w jeden, zachowując poprawną kolejność."""

    ihdr = None
    plte = None
    idat_data = b''
    iend = None

    for chunk in chunks:
        if chunk['type'] == 'IHDR':
            ihdr = chunk
        elif chunk['type'] == 'PLTE':
            plte = chunk
        elif chunk['type'] == 'IDAT':
            idat_data += chunk['data']
        elif chunk['type'] == 'IEND':
            iend = chunk

    # Sprawdź poprawność
    if ihdr is None or iend is None:
        raise ValueError("Brakuje obowiązkowego chunka IHDR lub IEND – plik PNG jest nieprawidłowy.")

    # Zbuduj pojedynczy chunk IDAT
    idat_chunk = None
    if idat_data:
        crc_input = b'IDAT' + idat_data
        crc = zlib.crc32(crc_input) & 0xffffffff
        idat_chunk = {
            'length': len(idat_data),
            'type': 'IDAT',
            'data': idat_data,
            'crc': struct.pack('>I', crc)
        }

    # Tworzymy listę w poprawnej kolejności
    final_chunks = [ihdr]
    if plte:
        final_chunks.append(plte)
    if idat_chunk:
        final_chunks.append(idat_chunk)
    final_chunks.append(iend)

    # Zapisujemy nowy plik
    with open(output_path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        for chunk in final_chunks:
            f.write(struct.pack('>I', chunk['length']))
            f.write(chunk['type'].encode('ascii'))
            f.write(chunk['data'])
            f.write(chunk['crc'])

    print(f"\nAnonimizacja zakończona. Zapisano jako '{output_path}'")
    print("Usunięto wszystkie ancillary chunki i naprawiono kolejność.")
