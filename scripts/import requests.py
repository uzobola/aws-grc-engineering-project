import requests

def decode_secret_message(url):
    lines = requests.get(url).text.strip().split('\n')
    
    grid = {}
    
    for line in lines[1:]:  # skip header
        parts = line.split('\t')
        if len(parts) >= 3:
            x, char, y = parts[0], parts[1], parts[2]
            grid[(int(x), int(y))] = char

    max_x = max(k[0] for k in grid)
    max_y = max(k[1] for k in grid)

    for y in range(max_y + 1):
        print(''.join(grid.get((x, y), ' ') for x in range(max_x + 1)))

decode_secret_message("https://docs.google.com/document/d/e/2PACX-1vSvM5gDINvt7npYHhp_XfsJvuntUhq184By5xO_pA4b_gCWeXb6dM6ZxwN8rE6S4ghUsCj2VKR21oEP/pub")