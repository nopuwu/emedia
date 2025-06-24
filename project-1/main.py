import sys
import png_handler
import image_processor

def main():
    """Główna funkcja programu."""
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Podaj ścieżkę do pliku PNG: ")

    try:
        # 1. Wczytaj i przeanalizuj plik PNG
        chunks = png_handler.read_png_file(file_path)

        # 2. Wyświetl informacje o chunkach
        print("\n=== Znalezione chunki ===")
        print(", ".join([chunk['type'] for chunk in chunks]))
        ihdr_info = png_handler.print_critical_chunks_info(chunks, False)
        
        # Wyświetlanie informacji z chunków ancillary
        png_handler.print_ancillary_chunks_info(chunks, ihdr_info['color_type'], ihdr_info['bit_depth']) 

        # 3. Oblicz i wyświetl FFT
        image_processor.compute_and_show_fft_from_file(file_path)

        # 4. Anonimizacja
        output_path = 'anonymized.png'
        png_handler.anonymize_png(chunks, output_path)

    except FileNotFoundError:
        print(f"Błąd: Plik '{file_path}' nie został znaleziony.")
    except ValueError as e:
        print(f"Błąd przetwarzania pliku PNG: {e}")
    except Exception as e:
        print(f"Wystąpił nieoczekiwany błąd: {e}")

if __name__ == "__main__":
    main()