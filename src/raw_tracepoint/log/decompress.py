#!/usr/bin/env python3
import gzip
import shutil
import argparse
import os
import sys

def decompress_gzip(input_path, output_path=None):
    """
    압축된 gzip 파일을 해제하여 원본 파일로 저장합니다.

    :param input_path: 압축된 gzip 파일의 경로
    :param output_path: 해제된 파일을 저장할 경로. 지정하지 않으면 .gz 확장자가 제거된 이름으로 저장
    """
    if not os.path.isfile(input_path):
        print(f"Error: '{input_path}' 파일이 존재하지 않습니다.", file=sys.stderr)
        sys.exit(1)
    
    if output_path is None:
        if input_path.endswith('.gz'):
            output_path = input_path[:-3]
        else:
            output_path = input_path + '.decompressed'
    
    try:
        with gzip.open(input_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        print(f"압축 해제 완료: '{output_path}'")
    except OSError as e:
        print(f"압축 해제 중 오류 발생: {e}", file=sys.stderr)
        sys.exit(1)

def decompress_stream(input_path, output_path=None):
    """
    스트리밍 방식으로 압축된 gzip 파일을 해제하여 원본 파일로 저장합니다.
    대용량 파일에 유용합니다.

    :param input_path: 압축된 gzip 파일의 경로
    :param output_path: 해제된 파일을 저장할 경로. 지정하지 않으면 .gz 확장자가 제거된 이름으로 저장
    """
    if not os.path.isfile(input_path):
        print(f"Error: '{input_path}' 파일이 존재하지 않습니다.", file=sys.stderr)
        sys.exit(1)
    
    if output_path is None:
        if input_path.endswith('.gz'):
            output_path = input_path[:-3]
        else:
            output_path = input_path + '.decompressed'
    
    chunk_size = 1024 * 1024  # 1MB 청크 크기
    
    try:
        with gzip.open(input_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    f_out.write(chunk)
        print(f"압축 해제 완료: '{output_path}'")
    except OSError as e:
        print(f"압축 해제 중 오류 발생: {e}", file=sys.stderr)
        sys.exit(1)

def parse_arguments():
    """
    커맨드라인 인자를 파싱합니다.

    :return: 파싱된 인자
    """
    parser = argparse.ArgumentParser(
        description="압축된 gzip 로그 파일을 해제하여 원본 로그를 복원합니다."
    )
    parser.add_argument(
        'input_file',
        help="압축된 gzip 로그 파일의 경로 (예: log/general.log.gz)"
    )
    parser.add_argument(
        '-o', '--output',
        help="해제된 로그를 저장할 파일의 경로. 지정하지 않으면 '.gz' 확장자가 제거된 이름으로 저장됩니다."
    )
    parser.add_argument(
        '--stream',
        action='store_true',
        help="스트리밍 방식으로 압축을 해제합니다. 대용량 파일에 유용합니다."
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    input_file = args.input_file
    output_file = args.output
    use_stream = args.stream

    if use_stream:
        decompress_stream(input_file, output_file)
    else:
        decompress_gzip(input_file, output_file)

if __name__ == "__main__":
    main()
