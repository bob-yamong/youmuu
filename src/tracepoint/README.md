![참고 사항](./image.png)

- syslog 적용시 handler.cpp에서 handler_syslog.cpp로 변경 해주어야함
- 위의 로그는 아래의 명령어로 확인 가능
```
sudo tail -f /var/log/syslog
```