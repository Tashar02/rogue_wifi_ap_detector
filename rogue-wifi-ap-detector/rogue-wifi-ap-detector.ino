// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Tashfin Shakeer Rhythm <tashfinshakeerrhythm@gmail.com>.
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "lwip/lwip_napt.h"
#include "lwip/tcpip.h"
#include "esp_netif.h"

#if __has_include("config.h")
# include "config.h"
#else
# define SECRET_TARGET_SSID	"YOUR_SSID_HERE"
# define SECRET_TARGET_PASS	"YOUR_PASSWORD_HERE"
#endif

/* Hardware PIN definitions */
#define BUZZER_PIN		0
#define BUTTON_PIN		1
#define LED_BLUE		2 /* Network Activity & Active Link */
#define LED_ORANGE		3 /* Local Warning & Alert State */
#define RGB_LED_PIN		8 /* ESP32-C6 Onboard Addressable RGB */
#define I2C_SDA			6
#define I2C_SCL			7

/* Display Settings */
#define SCREEN_WIDTH		128
#define SCREEN_HEIGHT		64
#define OLED_RESET		-1

/* Timing and Threshold Constants */
#define LONG_PRESS_MS		1000
#define DOUBLE_CLICK_MS		300
#define SHORT_PRESS_MS		400
#define DEBOUNCE_DELAY_MS	50
#define SCAN_TIMEOUT_MS		5000
#define PING_THRESHOLD		10
#define FLOOD_THRESHOLD		100

/* Acoustic Frequencies */
#define TONE_FREQ_SINGLE	2400
#define TONE_FREQ_DOUBLE	2100
#define TONE_FREQ_LONG		2500
#define TONE_FREQ_ALARM		2500
#define TONE_FREQ_SUCCESS	3000

/* Utility Macros */
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

/* Honeypot Network Settings */
const char *ap_ssid = "Scarlet ESP32-C6";
const char *ap_pass = "";

/* Target Hotspot Credentials (Feature 6 Option 1) */
const char *target_ssid = SECRET_TARGET_SSID;
const char *target_pass = SECRET_TARGET_PASS;

/* Global Variables */
uint8_t my_mac[6];
volatile uint32_t total_packet_count = 0;
volatile uint32_t interval_packet_count = 0;
char last_connected_mac[18] = "None";
volatile bool new_client_event = false;

/* Feature 5 (Port Scan) Variables */
int port_scan_count = 0;
unsigned long last_scan_time = 0;
WiFiServer server_21(21);	/* FTP Honeypot */
WiFiServer server_22(22);	/* SSH Honeypot */
WiFiServer server_80(80);	/* HTTP Honeypot */
WiFiServer server_443(443);	/* HTTPS Honeypot */

WiFiServer *honeypot_servers[] = {
	&server_21,
	&server_22,
	&server_80,
	&server_443,
};

/* Feature 6 (WiFi Repeater) Variables */
enum f6_substate {
	F6_SUB_MENU,
	F6_SUB_SCANNING,
	F6_SUB_CONNECTING,
	F6_SUB_ACTIVE,
	F6_SUB_FAILED
};

enum f6_substate f6_state = F6_SUB_MENU;
int f6_menu_index = 0;
char connected_ssid[33] = "None";
unsigned long f6_connect_start_time = 0;

/* State Machine */
enum app_state {
	STATE_MENU,
	STATE_RUN_F1,
	STATE_RUN_F2,
	STATE_RUN_F3,
	STATE_RUN_F4,
	STATE_RUN_F5,
	STATE_RUN_F6
};

enum button_action {
	ACTION_SINGLE,
	ACTION_DOUBLE,
	ACTION_LONG,
};

enum app_state state = STATE_MENU;
int menu_index = 0;
const int num_features = 6;

/* Debounced Button Variables */
int button_state = HIGH;
int last_flickerable_state = HIGH;
unsigned long last_debounce_time = 0;

unsigned long btn_press_time = 0;
unsigned long btn_release_time = 0;
bool is_waiting_for_double_click = false;
bool button_handled = false;

/* Non-blocking Timers */
unsigned long last_feature_update = 0;
bool blue_led_state = false;

/* Function Prototypes */
void set_rgb(uint8_t r, uint8_t g, uint8_t b);
void reset_button_state(void);
void draw_menu(void);
void draw_f6_menu(void);
void handle_button(void);
void execute_action(enum button_action action);
void setup_feature(void);
void exit_feature(void);
void start_f6_connection(void);

void feature_ping_monitor(void);
void feature_data_monitor(void);
void feature_client_logger(void);
void feature_flood_monitor(void);
void feature_portscan_monitor(void);
void feature_repeater(void);

void set_rgb(uint8_t r, uint8_t g, uint8_t b)
{
	neopixelWrite(RGB_LED_PIN, r, g, b);
}

void reset_button_state(void)
{
	button_state = digitalRead(BUTTON_PIN);
	last_flickerable_state = button_state;
	last_debounce_time = millis();
	is_waiting_for_double_click = false;
	button_handled = true;
}

static void display_begin_frame(void)
{
	display.clearDisplay();
	display.setCursor(0, 0);
	display.setTextColor(SSD1306_WHITE);
}

static void display_end_frame(bool show_exit)
{
	if (show_exit) {
		display.setCursor(0, 56);
		display.println("Dbl click = exit");
	}
	display.display();
}

/* Sniffer & Callbacks */
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *pkt;
	uint8_t *payload;
	bool is_to_me = true;
	int i;

	if (type != WIFI_PKT_DATA)
		return;

	pkt = (wifi_promiscuous_pkt_t *)buf;

	/* Ensure packet is long enough to safely read Address 1 (MAC) at offset 4 */
	if (pkt->rx_ctrl.sig_len < 10)
		return;

	payload = pkt->payload;

	for (i = 0; i < 6; i++) {
		if (payload[4 + i] != my_mac[i]) {
			is_to_me = false;
			break;
		}
	}

	if (is_to_me) {
		total_packet_count++;
		interval_packet_count++;
	}
}

void on_client_connect(WiFiEvent_t event, WiFiEventInfo_t info)
{
	uint8_t *mac = info.wifi_ap_staconnected.mac;

	snprintf(last_connected_mac, sizeof(last_connected_mac),
		 "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	new_client_event = true;
}

void setup(void)
{
	Serial.begin(115200);
	delay(500);
	Serial.println("\n--- Starting ESP32-C6 System ---");

	pinMode(BUZZER_PIN, OUTPUT);
	pinMode(LED_BLUE, OUTPUT);
	pinMode(LED_ORANGE, OUTPUT);
	pinMode(BUTTON_PIN, INPUT_PULLUP);

	digitalWrite(LED_BLUE, LOW);
	digitalWrite(LED_ORANGE, LOW);
	set_rgb(0, 15, 0); /* Dim Green: System Standby */

	Wire.begin(I2C_SDA, I2C_SCL);
	if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
		Serial.println(F("SSD1306 allocation failed"));
		for (;;);
	}

	WiFi.onEvent(on_client_connect, ARDUINO_EVENT_WIFI_AP_STACONNECTED);
	reset_button_state();
	draw_menu();
}

void loop(void)
{
	handle_button();

	switch (state) {
	case STATE_RUN_F1:
		feature_ping_monitor();
		break;
	case STATE_RUN_F2:
		feature_data_monitor();
		break;
	case STATE_RUN_F3:
		feature_client_logger();
		break;
	case STATE_RUN_F4:
		feature_flood_monitor();
		break;
	case STATE_RUN_F5:
		feature_portscan_monitor();
		break;
	case STATE_RUN_F6:
		feature_repeater();
		break;
	case STATE_MENU:
	default:
		break;
	}
}

void handle_button(void)
{
	int reading = digitalRead(BUTTON_PIN);
	unsigned long now = millis();
	unsigned long press_duration;

	if (reading != last_flickerable_state) {
		last_debounce_time = now;
		last_flickerable_state = reading;
	}

	if ((now - last_debounce_time) > DEBOUNCE_DELAY_MS) {
		if (reading != button_state) {
			button_state = reading;

			if (button_state == LOW) {
				btn_press_time = now;
				button_handled = false;
			} else {
				btn_release_time = now;
				press_duration = btn_release_time - btn_press_time;

				if (!button_handled) {
					if (press_duration < SHORT_PRESS_MS) {
						/* Immediate single click in main menu */
						if (state == STATE_MENU) {
							execute_action(ACTION_SINGLE);
						} else if (is_waiting_for_double_click) {
							execute_action(ACTION_DOUBLE);
							is_waiting_for_double_click = false;
						} else {
							is_waiting_for_double_click = true;
						}
					}
				}
			}
		}
	}

	if (button_state == LOW && !button_handled &&
	    (now - btn_press_time > LONG_PRESS_MS)) {
		execute_action(ACTION_LONG);
		button_handled = true;
		is_waiting_for_double_click = false;
	}

	if (is_waiting_for_double_click && (now - btn_release_time > DOUBLE_CLICK_MS) &&
	    button_state == HIGH) {
		execute_action(ACTION_SINGLE);
		is_waiting_for_double_click = false;
	}
}

void execute_action(enum button_action action)
{
	switch (action) {
	case ACTION_SINGLE:
		tone(BUZZER_PIN, TONE_FREQ_SINGLE, 60);
		if (state == STATE_MENU) {
			menu_index = (menu_index + 1) % num_features;
			draw_menu();
		} else if (state == STATE_RUN_F6 && f6_state == F6_SUB_MENU) {
			f6_menu_index = (f6_menu_index + 1) % 2;
			draw_f6_menu();
		}
		break;

	case ACTION_DOUBLE:
		if (state != STATE_MENU) {
			Serial.println("[Button] Double-click detected -> Exiting to Menu");
			tone(BUZZER_PIN, TONE_FREQ_DOUBLE, 120);
			exit_feature();
			state = STATE_MENU;
			draw_menu();
		}
		break;

	case ACTION_LONG:
		tone(BUZZER_PIN, TONE_FREQ_LONG, 300);
		if (state == STATE_MENU) {
			state = (enum app_state)(STATE_RUN_F1 + menu_index);
			setup_feature();
		} else if (state == STATE_RUN_F6 && f6_state == F6_SUB_MENU) {
			start_f6_connection();
		}
		break;
	}
}

void draw_menu(void)
{
	int i;
	const char *items[num_features] = {
		"1. Check AP pings",
		"2. Check AP data",
		"3. Log AP clients",
		"4. AP attack mon",
		"5. Port scan detect",
		"6. WiFi Repeater"
	};

	display_begin_frame();
	display.println("--- Main menu ---");
	display.println("---------------------");

	for (i = 0; i < num_features; i++) {
		if (i == menu_index) {
			display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
			display.print(">");
		} else {
			display.setTextColor(SSD1306_WHITE);
			display.print(" ");
		}
		display.println(items[i]);
	}

	display.display();
}

void draw_f6_menu(void)
{
	int i;
	const char *f6_items[2] = {
		"1. Target AP",
		"2. Open WiFi"
	};

	display_begin_frame();
	display.println("--- Repeater Mode ---");
	display.println("---------------------");

	for (i = 0; i < 2; i++) {
		if (i == f6_menu_index) {
			display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
			display.print(">");
		} else {
			display.setTextColor(SSD1306_WHITE);
			display.print(" ");
		}
		display.println(f6_items[i]);
	}

	display.display();
}

void setup_feature(void)
{
	Serial.print("[Feature] Setting up Feature Index: ");
	Serial.println(state);

	display_begin_frame();
	display.println("Starting feature...");
	display.display();

	WiFi.mode(WIFI_OFF);
	delay(100);

	digitalWrite(LED_BLUE, LOW);
	digitalWrite(LED_ORANGE, LOW);

	total_packet_count = 0;
	interval_packet_count = 0;
	last_feature_update = millis();

	if (state == STATE_RUN_F6) {
		WiFi.persistent(false);
		WiFi.mode(WIFI_AP_STA);
		WiFi.softAP(ap_ssid, ap_pass);
		WiFi.softAPmacAddress(my_mac);

		f6_state = F6_SUB_MENU;
		f6_menu_index = 0;
		strcpy(connected_ssid, "None");
		set_rgb(25, 25, 0); /* Yellow: Repeater Config Mode */
		reset_button_state();
		draw_f6_menu();
	} else {
		WiFi.mode(WIFI_AP);
		WiFi.softAP(ap_ssid, ap_pass);
		WiFi.softAPmacAddress(my_mac);
		strcpy(last_connected_mac, "None");

		if (state == STATE_RUN_F1 || state == STATE_RUN_F2) {
			esp_wifi_set_promiscuous(true);
			esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
			set_rgb(0, 20, 20); /* Cyan: Sniffer Active */
		}

		if (state == STATE_RUN_F3) {
			set_rgb(0, 20, 0); /* Green: Client Monitor */
		}

		if (state == STATE_RUN_F4) {
			esp_wifi_set_promiscuous(true);
			esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
			set_rgb(0, 20, 0); /* Green: Flood Sentry Active */
		}

		if (state == STATE_RUN_F5) {
			server_21.begin();
			server_22.begin();
			server_80.begin();
			server_443.begin();
			port_scan_count = 0;
			set_rgb(20, 0, 20); /* Purple: Honeypot Armed */
		}
		reset_button_state();
	}
}

void exit_feature(void)
{
	Serial.println("[Feature] Exiting current feature...");
	if (state == STATE_RUN_F6) {
		WiFi.scanDelete();
		WiFi.disconnect(true);
	} else {
		esp_wifi_set_promiscuous(false);
		esp_wifi_set_promiscuous_rx_cb(NULL);

		server_21.end();
		server_22.end();
		server_80.end();
		server_443.end();
	}

	WiFi.softAPdisconnect(true);
	WiFi.mode(WIFI_OFF);
	digitalWrite(LED_BLUE, LOW);
	digitalWrite(LED_ORANGE, LOW);
	set_rgb(0, 15, 0); /* Reset RGB to Standby Green */
	reset_button_state();
}

void start_f6_connection(void)
{
	f6_connect_start_time = millis();
	last_feature_update = millis();
	set_rgb(25, 25, 0); /* Yellow: Connecting */

	/* Disable Wi-Fi power save mode */
	WiFi.setSleep(false);
	WiFi.disconnect(false, true);
	delay(100);

	display_begin_frame();
	display.println("F6: WiFi Repeater");
	display.println("---------------------");

	if (f6_menu_index == 0) {
		Serial.print("[F6] Initiating STA connection to: ");
		Serial.println(target_ssid);

		f6_state = F6_SUB_CONNECTING;
		display.println("Connecting to:");
		display.println(target_ssid);
		display.display();

		WiFi.begin(target_ssid, target_pass);
		strncpy(connected_ssid, target_ssid, sizeof(connected_ssid) - 1);
	} else {
		Serial.println("[F6] Starting Async Open WiFi Search...");
		f6_state = F6_SUB_SCANNING;
		display.println("Searching Open WiFi...");
		display.println("Scanning nearest...");
		display.display();

		WiFi.scanDelete();
		WiFi.scanNetworks(true);
	}

	reset_button_state();
}

void feature_ping_monitor(void)
{
	unsigned long now = millis();

	if (now - last_feature_update < 1000)
		return;

	last_feature_update = now;

	/* Blue LED heartbeat */
	blue_led_state = !blue_led_state;
	digitalWrite(LED_BLUE, blue_led_state ? HIGH : LOW);

	display_begin_frame();
	display.println("Feature 1: Ping check");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);

	if (interval_packet_count > PING_THRESHOLD) {
		display.setCursor(0, 35);
		display.println("> Ping detected <");
		digitalWrite(LED_ORANGE, HIGH);
		set_rgb(30, 20, 0); /* Yellow: Ping Alert */
		tone(BUZZER_PIN, TONE_FREQ_SINGLE, 80);
	} else {
		digitalWrite(LED_ORANGE, LOW);
		set_rgb(0, 20, 20); /* Cyan: Normal Monitoring */
	}

	display.setCursor(0, 56);
	display.print("Pkts/sec: ");
	display.println(interval_packet_count);
	display.display();

	interval_packet_count = 0;
}

void feature_data_monitor(void)
{
	unsigned long now = millis();

	if (now - last_feature_update < 200)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("Feature 2: Data check");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);

	display.setCursor(0, 32);
	display.print("Total Rx: ");
	display.println(total_packet_count);

	/* Flash Blue LED & increase RGB intensity during active packet flow */
	if (interval_packet_count > 0) {
		digitalWrite(LED_BLUE, HIGH);
		set_rgb(0, 40, 40);
	} else {
		digitalWrite(LED_BLUE, LOW);
		set_rgb(0, 10, 10);
	}

	digitalWrite(LED_ORANGE, LOW);
	interval_packet_count = 0;

	display_end_frame(true);
}

void feature_client_logger(void)
{
	unsigned long now = millis();

	if (new_client_event) {
		tone(BUZZER_PIN, TONE_FREQ_SINGLE, 150);
		new_client_event = false;
	}

	if (now - last_feature_update < 500)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("Feature 3: Client log");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);
	display.println("Last connected:");
	display.println(last_connected_mac);

	if (WiFi.softAPgetStationNum() > 0) {
		digitalWrite(LED_BLUE, HIGH);
		set_rgb(0, 30, 0); /* Green: Active Client */
	} else {
		digitalWrite(LED_BLUE, LOW);
		set_rgb(0, 10, 0);
	}

	if (strcmp(last_connected_mac, "None") != 0)
		digitalWrite(LED_ORANGE, HIGH);
	else
		digitalWrite(LED_ORANGE, LOW);

	display_end_frame(true);
}

void feature_flood_monitor(void)
{
	unsigned long now = millis();

	if (now - last_feature_update < 1000)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("Feature 4: Flood mon");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);
	display.print("IP: ");
	display.println(WiFi.softAPIP());

	display.setCursor(0, 36);
	display.print("Traffic rate: ");
	display.println(interval_packet_count);

	if (interval_packet_count > FLOOD_THRESHOLD) {
		display.println(">> Flood attack! <<");
		digitalWrite(LED_ORANGE, HIGH);
		digitalWrite(LED_BLUE, LOW);
		set_rgb(40, 0, 0); /* Critical Red: Flood Attack */
		tone(BUZZER_PIN, TONE_FREQ_ALARM, 500);
	} else {
		digitalWrite(LED_ORANGE, LOW);
		digitalWrite(LED_BLUE, HIGH);
		set_rgb(0, 20, 0); /* Green: Protected */
	}

	display_end_frame(true);

	interval_packet_count = 0;
}

void feature_portscan_monitor(void)
{
	bool scan_hit = false;
	static unsigned long last_beep_time = 0;
	unsigned long now = millis();
	WiFiClient c;
	int i;

	/* Check for incoming connections on the honeypot array */
	for (i = 0; i < ARRAY_SIZE(honeypot_servers); i++) {
		if (!honeypot_servers[i]->hasClient())
			continue;

		c = honeypot_servers[i]->accept();
		c.flush();
		c.stop();
		scan_hit = true;
	}

	if (scan_hit) {
		port_scan_count++;
		last_scan_time = now;

		if (now - last_beep_time > 300) {
			tone(BUZZER_PIN, TONE_FREQ_ALARM, 150);
			last_beep_time = now;
		}
	}

	if (now - last_feature_update < 500)
		return;

	last_feature_update = now;

	digitalWrite(LED_BLUE, HIGH);

	display_begin_frame();
	display.println("Feature 5: Port Scan");
	display.println("---------------------");

	display.print("AP: ");
	display.println(ap_ssid);
	display.print("IP: ");
	display.println(WiFi.softAPIP());

	display.setCursor(0, 36);
	display.print("Honeypot Ports: 4");

	if (port_scan_count > 0) {
		display.setCursor(0, 46);
		display.println(">> SCAN DETECTED <<");
		digitalWrite(LED_ORANGE, HIGH);
		set_rgb(40, 0, 10); /* Red-Purple: Port Scan Triggered */
	} else {
		digitalWrite(LED_ORANGE, LOW);
		set_rgb(20, 0, 20); /* Purple: Honeypot Ready */
	}

	display_end_frame(true);

	if (port_scan_count > 0 && (now - last_scan_time > SCAN_TIMEOUT_MS)) {
		port_scan_count = 0;
		digitalWrite(LED_ORANGE, LOW);
	}
}

void feature_repeater(void)
{
	unsigned long now = millis();

	if (f6_state == F6_SUB_MENU)
		return;

	if (f6_state == F6_SUB_FAILED) {
		if (now - last_feature_update < 1000)
			return;

		last_feature_update = now;

		digitalWrite(LED_BLUE, LOW);
		digitalWrite(LED_ORANGE, HIGH);
		set_rgb(30, 0, 0); /* Red: Failure */

		display_begin_frame();
		display.println("F6: WiFi Repeater");
		display.println("---------------------");
		display.println("Connection Failed!");
		display_end_frame(true);
		return;
	}

	/* Infinite Non-blocking Open WiFi Scan targeting strongest RSSI */
	if (f6_state == F6_SUB_SCANNING) {
		int16_t scan_result = WiFi.scanComplete();

		if (scan_result >= 0) {
			bool open_found = false;
			char best_ssid[33] = "";
			int best_rssi = -999;
			int i;

			for (i = 0; i < scan_result; i++) {
				if (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) {
					int rssi = WiFi.RSSI(i);
					if (rssi > best_rssi) {
						best_rssi = rssi;
						strncpy(best_ssid, WiFi.SSID(i).c_str(), sizeof(best_ssid) - 1);
						open_found = true;
					}
				}
			}

			WiFi.scanDelete();

			if (open_found) {
				Serial.print("[F6] Found Strongest Open WiFi: ");
				Serial.print(best_ssid);
				Serial.print(" (RSSI: ");
				Serial.print(best_rssi);
				Serial.println(" dBm)");

				f6_state = F6_SUB_CONNECTING;
				f6_connect_start_time = millis();

				strncpy(connected_ssid, best_ssid, sizeof(connected_ssid) - 1);
				WiFi.begin(connected_ssid);

				display_begin_frame();
				display.println("F6: WiFi Repeater");
				display.println("---------------------");
				display.println("Connecting Open:");
				display.println(connected_ssid);
				display_end_frame(true);
			} else {
				/* Re-trigger infinite async scan if no open AP is currently visible */
				WiFi.scanNetworks(true);
			}
		}

		if (now - last_feature_update >= 500) {
			last_feature_update = now;
			blue_led_state = !blue_led_state;
			digitalWrite(LED_ORANGE, blue_led_state ? HIGH : LOW);
			digitalWrite(LED_BLUE, LOW);

			display_begin_frame();
			display.println("F6: WiFi Repeater");
			display.println("---------------------");
			display.println("Searching Open WiFi...");
			display.println("Finding nearest AP...");
			display_end_frame(true);
		}
		return;
	}

	if (f6_state == F6_SUB_CONNECTING) {
		if (WiFi.status() == WL_CONNECTED) {
			Serial.println("[F6] Connected successfully! Enabling NAPT & DNS...");
			f6_state = F6_SUB_ACTIVE;

#if defined(CONFIG_LWIP_IPV4_NAPT) || defined(IP_NAPT)
			/* 1. Enable NAPT safely with TCPIP core lock */
			LOCK_TCPIP_CORE();
			ip_napt_enable((uint32_t)WiFi.softAPIP(), 1);
			UNLOCK_TCPIP_CORE();

			/* 2. Configure SoftAP DHCP server to offer DNS to connected clients */
			esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
			if (ap_netif) {
				esp_netif_dns_info_t dns_info = {};
				dns_info.ip.type = IPADDR_TYPE_V4;

				IPAddress sta_dns = WiFi.dnsIP();
				if (sta_dns != IPAddress(0, 0, 0, 0)) {
					dns_info.ip.u_addr.ip4.addr = (uint32_t)sta_dns;
				} else {
					dns_info.ip.u_addr.ip4.addr = ESP_IP4TOADDR(8, 8, 8, 8);
				}

				esp_netif_dhcps_stop(ap_netif);
				esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns_info);

				uint8_t dns_offer = 1;
				esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &dns_offer, sizeof(dns_offer));
				esp_netif_dhcps_start(ap_netif);
			}
#endif
			digitalWrite(LED_ORANGE, LOW);
			digitalWrite(LED_BLUE, HIGH);
			set_rgb(0, 30, 0); /* Green: Connected & Bridging */
			tone(BUZZER_PIN, TONE_FREQ_SUCCESS, 250);
		} else if (now - f6_connect_start_time > 15000) {
			if (f6_menu_index == 1) {
				Serial.println("[F6] Connection timed out. Fallback to searching nearest open AP...");
				f6_state = F6_SUB_SCANNING;
				WiFi.disconnect(false, true);
				WiFi.scanDelete();
				WiFi.scanNetworks(true);
			} else {
				Serial.println("[F6] Target AP connection timed out.");
				f6_state = F6_SUB_FAILED;
				digitalWrite(LED_BLUE, LOW);
				digitalWrite(LED_ORANGE, HIGH);
				set_rgb(30, 0, 0);
				tone(BUZZER_PIN, TONE_FREQ_ALARM, 300);
			}
			return;
		}
	}

	if (now - last_feature_update < 1000)
		return;

	last_feature_update = now;

	display_begin_frame();
	display.println("F6: WiFi Repeater");
	display.println("---------------------");

	if (f6_state == F6_SUB_CONNECTING) {
		display.println("Connecting...");
		display.println(connected_ssid);
		blue_led_state = !blue_led_state;
		digitalWrite(LED_ORANGE, blue_led_state ? HIGH : LOW);
		digitalWrite(LED_BLUE, LOW);
	} else if (f6_state == F6_SUB_ACTIVE) {
		digitalWrite(LED_ORANGE, LOW);
		digitalWrite(LED_BLUE, HIGH);
		set_rgb(0, 30, 0);

		display.print("STA: ");
		display.println(connected_ssid);
		display.print("IP: ");
		display.println(WiFi.localIP());
		display.print("Clients: ");
		display.println(WiFi.softAPgetStationNum());
	}

	display_end_frame(true);
}
