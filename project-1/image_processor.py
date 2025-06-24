import numpy as np
import matplotlib.pyplot as plt
from PIL import Image

import numpy as np
from PIL import Image
import matplotlib.pyplot as plt

def compute_and_show_fft_from_file(file_path):
    """
    Oblicza i wyświetla widmo amplitudowe oraz widmo fazowe za pomocą transformaty Fouriera,
    a także obraz po odwróconej transformacie Fouriera.
    """
    try:
        img = Image.open(file_path)
        img_array = np.array(img)

        # Konwersja obrazu do skali szarości
        gray_img_pil = img.convert('L') # L - skala szarości
        gray_img = np.array(gray_img_pil)

        # Obliczanie FFT
        fft_img = np.fft.fft2(gray_img)
        fft_img_shifted = np.fft.fftshift(fft_img) # Przesunięcie składowej zerowej do centrum

        # Widmo Amplitudowe
        # Dodajemy małą stałą, aby uniknąć logarytmowania zera
        magnitude_spectrum = 20 * np.log(np.abs(fft_img_shifted) + 1e-9) 

        # Widmo Fazowe
        phase_spectrum = np.angle(fft_img_shifted)

        # Odwrócenie FFT
        ifft_img = np.fft.ifft2(fft_img).real

        plt.figure(figsize=(16, 8))

        plt.subplot(1, 4, 1)
        plt.imshow(gray_img, cmap='gray')
        plt.title("Oryginalny obraz")
        plt.axis('off')

        plt.subplot(1, 4, 2)
        plt.imshow(magnitude_spectrum)
        plt.title("Widmo Fouriera (amplituda w skali log)")
        plt.axis('off')
        
        plt.subplot(1, 4, 3)
        plt.imshow(phase_spectrum)
        plt.title("Widmo Fazowe")
        plt.axis('off')

        plt.subplot(1, 4, 4)
        plt.imshow(ifft_img, cmap='gray')
        plt.title("Obraz po IFFT")
        plt.axis('off')

        plt.tight_layout()
        plt.show()

    except FileNotFoundError:
        print(f"Błąd: Plik '{file_path}' nie został znaleziony.")
    except Exception as e:
        print(f"Błąd podczas obliczania FFT: {e}")
