import zlib
import sys

def decompress_stream(input_file, output_file):
    """
    스트리밍 방식으로 zlib 압축된 데이터를 해제하여 원본 로그를 추출합니다.
    
    Args:
        input_file (str): 압축된 로그 파일 경로.
        output_file (str): 해제된 로그를 저장할 파일 경로.
    """
    decompressor = zlib.decompressobj()
    
    try:
        with open(input_file, 'rb') as fin, open(output_file, 'w', encoding='utf-8') as fout:
            while True:
                chunk = fin.read(1024 * 1024)  # 1MB씩 읽기
                if not chunk:
                    break
                try:
                    decompressed = decompressor.decompress(chunk)
                    fout.write(decompressed.decode('utf-8', errors='replace'))
                except zlib.error as e:
                    print(f"Decompression error: {e}")
                    break
            
            # 남아있는 데이터를 플러시
            try:
                decompressed = decompressor.flush()
                fout.write(decompressed.decode('utf-8', errors='replace'))
            except zlib.error as e:
                print(f"Decompression flush error: {e}")
    
        print(f"Decompression completed. Logs saved to '{output_file}'.")
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except IOError as e:
        print(f"IOError: {e}")
        sys.exit(1)

def main():
    input_file = 'general.log'          # 압축된 로그 파일 경로
    output_file = 'log_decompressed.log'    # 해제된 로그를 저장할 파일 경로
    decompress_stream(input_file, output_file)

if __name__ == "__main__":
    main()
