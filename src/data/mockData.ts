export interface Asset {
  id: string;
  ip: string;
  mac: string;
  vendor: string;
  deviceType: string;
  os: string;
  confidence: number;
  vlan: number;
  status: 'online' | 'offline' | 'unknown';
  riskScore: number;
  lastSeen: string;
  firstSeen: string;
  ja3?: string;
  userAgent?: string;
  dhcpFingerprint?: string;
  ports: number[];
  protocols: string[];
  vulnerabilities: Vulnerability[];
  activities: Activity[];
}

export interface Vulnerability {
  cve: string;
  cvss: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  published: string;
  deviceCount?: number;
}

export interface Activity {
  timestamp: string;
  action: string;
  detail: string;
}

export interface Alert {
  id: string;
  timestamp: string;
  type: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  message: string;
  source: string;
  status: 'new' | 'investigating' | 'resolved';
}

export interface NetworkFlow {
  source: string;
  destination: string;
  port: number;
  protocol: string;
  bytes: number;
  packets: number;
}

export const assets: Asset[] = [
  {
    id: '1', ip: '10.0.1.10', mac: '00:1A:2B:3C:4D:5E', vendor: 'GE Healthcare', deviceType: 'IoMT', os: 'Embedded Linux', confidence: 95, vlan: 10, status: 'online', riskScore: 85,
    lastSeen: '2026-04-08 14:30', firstSeen: '2025-06-12 09:00',
    ja3: 'a0e9f5d64349fb13191bc781f81f42e1', userAgent: 'GE-MRI/3.2', dhcpFingerprint: '1,28,2,3,15,6,12',
    ports: [80, 443, 8080, 2575], protocols: ['HTTP', 'HTTPS', 'DICOM', 'HL7'],
    vulnerabilities: [
      { cve: 'CVE-2024-1234', cvss: 9.1, severity: 'Critical', description: 'Lỗ hổng thực thi mã từ xa trong giao thức DICOM', published: '2024-03-15' },
      { cve: 'CVE-2024-5678', cvss: 7.5, severity: 'High', description: 'Lỗ hổng xác thực yếu trong web interface', published: '2024-05-20' },
    ],
    activities: [
      { timestamp: '2026-04-08 14:30', action: 'Kết nối DICOM', detail: 'Gửi dữ liệu MRI đến PACS server 10.0.1.50' },
      { timestamp: '2026-04-08 13:15', action: 'Cập nhật firmware', detail: 'Tải firmware v3.2.1 từ update.gehealthcare.com' },
      { timestamp: '2026-04-08 10:00', action: 'Kết nối HTTP', detail: 'Truy cập web console từ 10.0.2.5' },
    ],
  },
  {
    id: '2', ip: '10.0.1.20', mac: '00:2B:3C:4D:5E:6F', vendor: 'Philips', deviceType: 'IoMT', os: 'Windows 10 IoT', confidence: 92, vlan: 10, status: 'online', riskScore: 72,
    lastSeen: '2026-04-08 14:25', firstSeen: '2025-08-01 08:30',
    ja3: 'b3e9f5d64349fb13191bc781f81f42e2', userAgent: 'Philips-CT/2.1',
    ports: [80, 443, 104], protocols: ['HTTP', 'HTTPS', 'DICOM'],
    vulnerabilities: [
      { cve: 'CVE-2024-9012', cvss: 6.8, severity: 'Medium', description: 'Lỗ hổng XSS trong giao diện quản trị', published: '2024-07-10' },
    ],
    activities: [
      { timestamp: '2026-04-08 14:25', action: 'Quét CT', detail: 'Gửi 245MB dữ liệu CT scan đến PACS' },
    ],
  },
  {
    id: '3', ip: '10.0.2.15', mac: '00:3C:4D:5E:6F:7A', vendor: 'Hikvision', deviceType: 'IoT', os: 'Embedded Linux', confidence: 88, vlan: 20, status: 'online', riskScore: 91,
    lastSeen: '2026-04-08 14:28', firstSeen: '2025-03-20 14:00',
    ja3: 'c4e9f5d64349fb13191bc781f81f42e3',
    ports: [80, 443, 554, 8000], protocols: ['HTTP', 'HTTPS', 'RTSP'],
    vulnerabilities: [
      { cve: 'CVE-2023-6789', cvss: 9.8, severity: 'Critical', description: 'Lỗ hổng bypass xác thực - cho phép truy cập từ xa không cần mật khẩu', published: '2023-11-05' },
      { cve: 'CVE-2024-2345', cvss: 8.2, severity: 'High', description: 'Lỗ hổng tràn bộ đệm trong xử lý RTSP', published: '2024-02-18' },
    ],
    activities: [
      { timestamp: '2026-04-08 14:28', action: 'Streaming RTSP', detail: 'Stream video liên tục đến NVR 10.0.2.100' },
      { timestamp: '2026-04-08 12:00', action: 'Kết nối ra ngoài', detail: 'Kết nối tới 203.0.113.50:8080 (Trung Quốc)' },
    ],
  },
  {
    id: '4', ip: '10.0.3.5', mac: '00:4D:5E:6F:7A:8B', vendor: 'Dell', deviceType: 'Workstation', os: 'Windows 11 Pro', confidence: 99, vlan: 30, status: 'online', riskScore: 35,
    lastSeen: '2026-04-08 14:32', firstSeen: '2025-01-10 08:00',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    ports: [135, 445, 3389], protocols: ['SMB', 'RDP'],
    vulnerabilities: [],
    activities: [
      { timestamp: '2026-04-08 14:32', action: 'Đăng nhập RDP', detail: 'Phiên RDP từ 10.0.3.10' },
    ],
  },
  {
    id: '5', ip: '10.0.1.50', mac: '00:5E:6F:7A:8B:9C', vendor: 'HP', deviceType: 'Server', os: 'Ubuntu 22.04', confidence: 98, vlan: 10, status: 'online', riskScore: 45,
    lastSeen: '2026-04-08 14:33', firstSeen: '2024-11-05 10:00',
    ports: [22, 80, 443, 104, 2575, 5432], protocols: ['SSH', 'HTTP', 'HTTPS', 'DICOM', 'HL7', 'PostgreSQL'],
    vulnerabilities: [
      { cve: 'CVE-2024-3456', cvss: 5.3, severity: 'Medium', description: 'Lỗ hổng rò rỉ thông tin trong OpenSSH', published: '2024-04-22' },
    ],
    activities: [
      { timestamp: '2026-04-08 14:33', action: 'Nhận DICOM', detail: 'Nhận dữ liệu từ 3 thiết bị IoMT' },
    ],
  },
  {
    id: '6', ip: '10.0.4.100', mac: '00:6F:7A:8B:9C:AD', vendor: 'Unknown', deviceType: 'Chưa xác định', os: 'Không xác định', confidence: 25, vlan: 40, status: 'unknown', riskScore: 60,
    lastSeen: '2026-04-08 13:50', firstSeen: '2026-04-08 13:45',
    ports: [80, 443, 8443], protocols: ['HTTP', 'HTTPS'],
    vulnerabilities: [],
    activities: [
      { timestamp: '2026-04-08 13:50', action: 'Quét mạng', detail: 'Quét port trên dải 10.0.0.0/16' },
      { timestamp: '2026-04-08 13:45', action: 'Xuất hiện mới', detail: 'Thiết bị mới kết nối vào mạng' },
    ],
  },
  {
    id: '7', ip: '10.0.2.30', mac: '00:7A:8B:9C:AD:BE', vendor: 'Siemens', deviceType: 'IoMT', os: 'VxWorks', confidence: 90, vlan: 10, status: 'online', riskScore: 78,
    lastSeen: '2026-04-08 14:20', firstSeen: '2025-04-15 11:00',
    ports: [80, 443, 104], protocols: ['HTTP', 'HTTPS', 'DICOM'],
    vulnerabilities: [
      { cve: 'CVE-2024-7890', cvss: 8.5, severity: 'High', description: 'Lỗ hổng leo thang đặc quyền trong VxWorks RTOS', published: '2024-08-01' },
    ],
    activities: [
      { timestamp: '2026-04-08 14:20', action: 'Chẩn đoán hình ảnh', detail: 'Gửi kết quả siêu âm đến workstation 10.0.3.5' },
    ],
  },
  {
    id: '8', ip: '10.0.5.10', mac: '00:8B:9C:AD:BE:CF', vendor: 'Cisco', deviceType: 'Network', os: 'IOS-XE 17.6', confidence: 99, vlan: 50, status: 'online', riskScore: 20,
    lastSeen: '2026-04-08 14:35', firstSeen: '2024-06-01 08:00',
    ports: [22, 23, 161, 443], protocols: ['SSH', 'Telnet', 'SNMP', 'HTTPS'],
    vulnerabilities: [],
    activities: [
      { timestamp: '2026-04-08 14:35', action: 'SNMP Poll', detail: 'Phản hồi SNMP từ NMS 10.0.5.1' },
    ],
  },
];

export const vulnerabilities: Vulnerability[] = [
  { cve: 'CVE-2023-6789', cvss: 9.8, severity: 'Critical', description: 'Lỗ hổng bypass xác thực Hikvision', published: '2023-11-05', deviceCount: 1 },
  { cve: 'CVE-2024-1234', cvss: 9.1, severity: 'Critical', description: 'Thực thi mã từ xa trong giao thức DICOM', published: '2024-03-15', deviceCount: 1 },
  { cve: 'CVE-2024-7890', cvss: 8.5, severity: 'High', description: 'Leo thang đặc quyền trong VxWorks RTOS', published: '2024-08-01', deviceCount: 1 },
  { cve: 'CVE-2024-5678', cvss: 7.5, severity: 'High', description: 'Xác thực yếu trong web interface GE Healthcare', published: '2024-05-20', deviceCount: 1 },
  { cve: 'CVE-2024-2345', cvss: 8.2, severity: 'High', description: 'Tràn bộ đệm trong xử lý RTSP', published: '2024-02-18', deviceCount: 1 },
  { cve: 'CVE-2024-9012', cvss: 6.8, severity: 'Medium', description: 'XSS trong giao diện quản trị Philips', published: '2024-07-10', deviceCount: 1 },
  { cve: 'CVE-2024-3456', cvss: 5.3, severity: 'Medium', description: 'Rò rỉ thông tin trong OpenSSH', published: '2024-04-22', deviceCount: 1 },
];

export const alerts: Alert[] = [
  { id: 'a1', timestamp: '2026-04-08 14:28', type: 'Kết nối bất thường', severity: 'Critical', message: 'Camera Hikvision 10.0.2.15 kết nối ra IP nước ngoài 203.0.113.50', source: '10.0.2.15', status: 'new' },
  { id: 'a2', timestamp: '2026-04-08 13:45', type: 'Thiết bị mới', severity: 'High', message: 'Thiết bị không xác định xuất hiện trên VLAN 40 (10.0.4.100)', source: '10.0.4.100', status: 'new' },
  { id: 'a3', timestamp: '2026-04-08 13:50', type: 'Quét mạng', severity: 'Critical', message: 'Phát hiện quét port từ 10.0.4.100 trên dải 10.0.0.0/16', source: '10.0.4.100', status: 'investigating' },
  { id: 'a4', timestamp: '2026-04-08 12:00', type: 'IoT ra Internet', severity: 'High', message: 'Thiết bị IoMT GE Healthcare cập nhật firmware không theo lịch', source: '10.0.1.10', status: 'investigating' },
  { id: 'a5', timestamp: '2026-04-08 10:30', type: 'Lỗ hổng mới', severity: 'Medium', message: 'Phát hiện CVE-2024-1234 ảnh hưởng đến thiết bị MRI GE Healthcare', source: '10.0.1.10', status: 'resolved' },
  { id: 'a6', timestamp: '2026-04-07 22:15', type: 'Hành vi bất thường', severity: 'Medium', message: 'Lưu lượng DICOM bất thường từ 10.0.1.20 vào ban đêm', source: '10.0.1.20', status: 'resolved' },
  { id: 'a7', timestamp: '2026-04-07 18:00', type: 'Xác thực thất bại', severity: 'Low', message: '5 lần đăng nhập thất bại vào switch Cisco 10.0.5.10', source: '10.0.5.10', status: 'resolved' },
];

export const networkFlows: NetworkFlow[] = [
  { source: '10.0.1.10', destination: '10.0.1.50', port: 104, protocol: 'DICOM', bytes: 256000000, packets: 185000 },
  { source: '10.0.1.20', destination: '10.0.1.50', port: 104, protocol: 'DICOM', bytes: 512000000, packets: 320000 },
  { source: '10.0.2.15', destination: '10.0.2.100', port: 554, protocol: 'RTSP', bytes: 1024000000, packets: 750000 },
  { source: '10.0.2.15', destination: '203.0.113.50', port: 8080, protocol: 'HTTP', bytes: 4500, packets: 12 },
  { source: '10.0.3.5', destination: '10.0.1.50', port: 443, protocol: 'HTTPS', bytes: 15000000, packets: 12000 },
  { source: '10.0.4.100', destination: '10.0.0.0/16', port: 0, protocol: 'TCP SYN', bytes: 2400, packets: 65535 },
  { source: '10.0.2.30', destination: '10.0.3.5', port: 104, protocol: 'DICOM', bytes: 128000000, packets: 95000 },
  { source: '10.0.5.1', destination: '10.0.5.10', port: 161, protocol: 'SNMP', bytes: 45000, packets: 300 },
];

export const trafficData = [
  { time: '00:00', inbound: 120, outbound: 85 },
  { time: '02:00', inbound: 45, outbound: 30 },
  { time: '04:00', inbound: 30, outbound: 20 },
  { time: '06:00', inbound: 80, outbound: 55 },
  { time: '08:00', inbound: 350, outbound: 280 },
  { time: '10:00', inbound: 520, outbound: 410 },
  { time: '12:00', inbound: 480, outbound: 390 },
  { time: '14:00', inbound: 550, outbound: 430 },
  { time: '16:00', inbound: 420, outbound: 340 },
  { time: '18:00', inbound: 280, outbound: 220 },
  { time: '20:00', inbound: 180, outbound: 140 },
  { time: '22:00', inbound: 150, outbound: 100 },
];

export const deviceTypeDistribution = [
  { name: 'IoMT', value: 3, fill: 'hsl(var(--chart-1))' },
  { name: 'IoT', value: 1, fill: 'hsl(var(--chart-3))' },
  { name: 'Workstation', value: 1, fill: 'hsl(var(--chart-2))' },
  { name: 'Server', value: 1, fill: 'hsl(var(--chart-5))' },
  { name: 'Network', value: 1, fill: 'hsl(var(--chart-1))' },
  { name: 'Chưa xác định', value: 1, fill: 'hsl(var(--chart-4))' },
];
