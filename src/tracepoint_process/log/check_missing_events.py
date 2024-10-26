import glob
import re
import sys

# 겹치는 cnt 값의 수를 찾기
def count_duplicate_cnts(cnts):
    """
    주어진 cnt 리스트에서 중복된 cnt 값의 수를 반환합니다.
    """
    cnt_set = set(cnts)
    return len(cnts) - len(cnt_set)

def extract_cnts_from_file(filename):
    """
    주어진 파일에서 cnt 값을 추출하여 리스트로 반환합니다.
    """
    cnt_pattern = re.compile(r'\[(\d+)\]')
    cnts = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                match = cnt_pattern.search(line)
                if match:
                    cnt = int(match.group(1))
                    cnts.append(cnt)
    except Exception as e:
        print(f"파일을 읽는 중 오류 발생: {filename}\n오류: {e}")
    return cnts

def merge_and_extract_cnts(log_directory='.'):
    """
    지정된 디렉토리 내의 모든 worker_*.log 파일에서 cnt 값을 추출하여 반환합니다.
    """
    log_files = glob.glob(f"{log_directory}/*.log")
    if not log_files:
        print("로그 파일을 찾을 수 없습니다. 현재 디렉토리 또는 지정된 디렉토리를 확인하세요.")
        sys.exit(1)
    
    all_cnts = []
    for log_file in log_files:
        print(f"파일에서 cnt 추출 중: {log_file}")
        cnts = extract_cnts_from_file(log_file)
        all_cnts.extend(cnts)
    
    return all_cnts

def find_missing_cnts(sorted_cnts):
    """
    정렬된 cnt 리스트에서 누락된 cnt 값을 찾아 반환합니다.
    """
    if not sorted_cnts:
        return []
    
    missing = []
    start = sorted_cnts[0]
    end = sorted_cnts[-1]
    expected = set(range(start, end + 1))
    actual = set(sorted_cnts)
    missing = sorted(expected - actual)
    return missing

def main():
    """
    메인 함수: 로그 파일에서 cnt 값을 추출하고, 누락된 이벤트를 확인합니다.
    """
    import argparse

    parser = argparse.ArgumentParser(description="로그 파일에서 누락된 이벤트 확인")
    parser.add_argument('-d', '--dir', type=str, default='.', help='로그 파일이 있는 디렉토리 경로 (기본값: 현재 디렉토리)')
    args = parser.parse_args()

    log_directory = args.dir
    print(f"로그 파일 검색 디렉토리: {log_directory}")

    # cnt 값 추출
    all_cnts = merge_and_extract_cnts(log_directory)
    if not all_cnts:
        print("추출된 cnt 값이 없습니다.")
        sys.exit(1)
    
    # cnt 값 정렬 및 중복 제거
    sorted_unique_cnts = sorted(set(all_cnts))
    print(f"총 추출된 cnt 값 수: {len(sorted_unique_cnts)}")
    print(f"중복된 cnt 값 수: {count_duplicate_cnts(all_cnts)}")

    # 연속성 검사
    missing_cnts = find_missing_cnts(sorted_unique_cnts)
    if missing_cnts:
        print(f"누락된 cnt 값이 {len(missing_cnts)}개 있습니다:")
        print(*missing_cnts,sep=', ')
    else:
        print("누락된 cnt 값이 없습니다. 모든 이벤트가 정상적으로 기록되었습니다.")

if __name__ == "__main__":
    main()
