from PIL import Image

# Create a simple square image for the favicon
favicon_size = (16, 16)
favicon_color = (255, 0, 0)  # Red color

# Create an image
favicon = Image.new('RGB', favicon_size, favicon_color)
favicon.save('favicon.ico', format='ICO')

