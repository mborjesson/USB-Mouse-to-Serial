/*
 * USB Mouse to Serial - Translates USB mouse inputs to serial mouse protocol
 *
 * Copyright (c) 2018 Martin Börjesson
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <libevdev/libevdev.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <regex.h>
#include <dirent.h>
#include <getopt.h>
#include <locale.h>
#include <math.h>

/* Protocol reset timeout in milliseconds. Set to 0 to disable. */
#define PROTOCOL_RESET_TIMEOUT 1000

/* The queue size for mouse buttons */
#define MOUSE_BUTTON_QUEUE_SIZE 10

#define THREE_BUTTONS 1<<10
#define MOUSE_WHEEL 1<<11
#define SERIAL_7N1 1<<12
#define SERIAL_8N1 1<<13

#define PROTOCOL_MICROSOFT (1<<0|SERIAL_7N1)
#define PROTOCOL_MICROSOFT_WHEEL (1<<1|THREE_BUTTONS|MOUSE_WHEEL|SERIAL_7N1)
#define PROTOCOL_LOGITECH (1<<2|THREE_BUTTONS|SERIAL_7N1)
#define PROTOCOL_MOUSE_SYSTEMS (1<<3|THREE_BUTTONS|SERIAL_8N1)

static volatile int running = 0;
static volatile int input_running = 0;
static volatile int mouse_suspend = 0;

static pthread_mutex_t input_mutex;

static struct mouse_button_t {
	int down;
	int changed;
} mouse_button_t;

static struct mouse_button_queue_t {
	struct mouse_button_t queue[MOUSE_BUTTON_QUEUE_SIZE];
	int size;
} mouse_button_queue_t;

static int mouse_x = 0;
static int mouse_y = 0;
static int mouse_wheel = 0;
static struct mouse_button_queue_t mouse_left;
static struct mouse_button_queue_t mouse_middle;
static struct mouse_button_queue_t mouse_right;

static int requested_protocol = PROTOCOL_MICROSOFT;
static int mouse_protocol = PROTOCOL_MICROSOFT;

static float x_multiplier = 1.0;
static float y_multiplier = 1.0;
static int enable_multiplier = 0;

static int mouse_swap = 0;

static struct termios original_termios_options;

static int verbose_level = 0;

static int requested_output_rate = 0; /* In nanoseconds */
static int output_rate = 0; /* In nanoseconds */
static int mouse_auto_suspend = 0;
static char original_suspend_mode[32];

static int output_test = 0;

static void verbose(int level, const char *format, ...) {
	if (level <= verbose_level) {
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}
}

static void inthandler(int d) {
	printf("Shutting down...\n");
	running = 0;
	input_running = 0;
}

static int write_char(int fd, char c) {
	return write(fd, &c, sizeof(char));
}

static void sleep_ms(int ms) {
	struct timespec ts;
	ts.tv_sec = ms/1000;
	ms -= (ts.tv_sec*1000);
	ts.tv_nsec = ms*1000000;

	nanosleep(&ts, NULL);
}

static int clamp(int value, int min, int max) {
	if (value < min) {
		return min;
	} else if (value > max) {
		return max;
	}
	return value;
}

static void clock_diff(const struct timespec* start, const struct timespec* end, struct timespec* result) {
	if ((end->tv_nsec-start->tv_nsec) < 0) {
		if (end->tv_sec > start->tv_sec) {
			result->tv_sec = end->tv_sec-start->tv_sec-1;
			result->tv_nsec = 1000000000+end->tv_nsec-start->tv_nsec;
		} else {
			result->tv_sec = 0;
			result->tv_nsec = 0;
		}
	} else {
		result->tv_sec = end->tv_sec-start->tv_sec;
		result->tv_nsec = end->tv_nsec-start->tv_nsec;
	}
}

static unsigned int clock_tomilliseconds(const struct timespec* ts) {
	return ts->tv_sec*1000+ts->tv_nsec/1000000;
}

static unsigned int clock_now(struct timespec* ts) {
	clock_gettime(CLOCK_MONOTONIC, ts);
}

static unsigned int clock_elapsed(const struct timespec* start) {
	struct timespec current;
	clock_now(&current);
	clock_diff(start, &current, &current);
	return clock_tomilliseconds(&current);
}

static int write_blocking(int fd, const void* buf, size_t size, const struct timespec* block) {
	struct timespec start, end;
	int r;
	clock_now(&start);
	r = write(fd, buf, size);
	clock_now(&end);
	clock_diff(&start, &end, &start);
	clock_diff(&start, block, &start);
	nanosleep(&start, NULL);
	return r;
}

static int protocol_has_feature(int protocol, int state) {
	return (protocol&state) == state;
}

static void set_default_output_rate(int protocol) {
	if (protocol_has_feature(protocol, SERIAL_8N1)) {
		output_rate = 8333333; /* (1 start bit + 8 data bits + 1 stop bits) / 1200 baud */
	} else {
		output_rate = 7500000; /* (1 start bit + 7 data bits + 1 stop bits) / 1200 baud */
	}
}

static const char* get_protocol_name(int protocol) {
	if (protocol == PROTOCOL_LOGITECH) {
		return "Logitech 3-button mouse";
	} else if (protocol == PROTOCOL_MICROSOFT_WHEEL) {
		return "Microsoft 3-button wheel mouse";
	} else if (protocol == PROTOCOL_MICROSOFT) {
		return "Microsoft 2-button mouse";
	} else if (protocol == PROTOCOL_MOUSE_SYSTEMS) {
		return "Mouse Systems 3-button mouse";
	}
	return "Unknown protocol";
}

static int push_button_queue(struct mouse_button_queue_t* queue, int down) {
	if (queue->size < MOUSE_BUTTON_QUEUE_SIZE-1) {
		queue->queue[queue->size].down = down;
		queue->queue[queue->size].changed = 1;
		queue->size++;
		return 1;
	}
	printf("Queue full!");
	return 0;
}

static int poll_button_queue(struct mouse_button_queue_t* queue, struct mouse_button_t* result) {
	if (queue->size > 0) {
		memcpy(result, &queue->queue[queue->size-1], sizeof(struct mouse_button_t));
		return 1;
	}
	return 0;
}

static int pop_button_queue(struct mouse_button_queue_t* queue, struct mouse_button_t* result) {
	if (poll_button_queue(queue, result)) {
		if (queue->size > 1) {
			memmove(queue->queue, queue->queue+1, (queue->size-1)*sizeof(struct mouse_button_t));
		}
		queue->size--;
		return 1;
	}
	return 0;
}

/*
 * Input
 *
 * These functions handle all input from USB using libevdev
 */

static int open_input(const char* device) {
	int fd;
	int rc;
	struct libevdev* dev;

	fd = open(device, O_RDONLY | O_NONBLOCK);

	if (fd < 0) {
		return -1;
	}

	/* Check if it's a mouse */
	rc = libevdev_new_from_fd(fd, &dev);
	if (rc < 0) {
		fprintf(stderr, "Error: %d %s\n", -rc, strerror(-rc));
		return -1;
	}
	rc = libevdev_has_event_type(dev, EV_REL) &&
		libevdev_has_event_code(dev, EV_REL, REL_X) &&
		libevdev_has_event_code(dev, EV_REL, REL_Y) &&
		libevdev_has_event_code(dev, EV_KEY, BTN_LEFT) &&
		libevdev_has_event_code(dev, EV_KEY, BTN_MIDDLE) &&
		libevdev_has_event_code(dev, EV_KEY, BTN_RIGHT);

	libevdev_free(dev);

	if (rc) {
		return fd;
	}

	close(fd);

	return -1;
}

static int find_input() {
	regex_t mouse_regex;
	int mouse_fd;
	DIR* dir;
	struct dirent* dp;
	char full_path[1024];

	regcomp(&mouse_regex, "event-mouse", 0);

	const char *dir_name = "/dev/input/by-id";
	if (!(dir = opendir(dir_name))) {
		perror("Unable to open /dev/input/by-id");
		return -1;
	}

	do {
		errno = 0;
		
		if (dp = readdir(dir)) {
			if(!regexec(&mouse_regex, dp->d_name, 0, NULL, 0)) {
				sprintf(full_path, "%s/%s", dir_name, dp->d_name);
				mouse_fd = open_input(full_path);

				break;
			}

		}
	} while (dp);

	closedir(dir);

	regfree(&mouse_regex);

	return mouse_fd;
}

static int find_power_control(int id_vendor, int id_provider) {
	int fd;
	DIR* dir;
	struct dirent* dp;
	char full_path[1024];
	char data[5];
	int p, v, r;

	const char *dir_name = "/sys/bus/usb/devices";
	if (!(dir = opendir(dir_name))) {
		perror("Unable to open /sys/bus/usb/devices");
		return -1;
	}

	memset(&data, 0, sizeof(data));

	do {
		errno = 0;
		if (dp = readdir(dir)) {
			snprintf(full_path, sizeof(full_path)-1, "%s/%s/idProduct", dir_name, dp->d_name);
			fd = open(full_path, O_RDONLY | O_NONBLOCK);
			if (fd != -1) {
				r = read(fd, data, 4);
				p = (int)strtol(data, NULL, 16);
				close(fd);

				if (p == id_provider) {
					snprintf(full_path, sizeof(full_path)-1, "%s/%s/idVendor", dir_name, dp->d_name);
					fd = open(full_path, O_RDONLY | O_NONBLOCK);
					if (fd != -1) {
						r = read(fd, data, 4);
						v = (int)strtol(data, NULL, 16);
						close(fd);

						if (v == id_vendor) {
							snprintf(full_path, sizeof(full_path)-1, "%s/%s/power/control", dir_name, dp->d_name);
							fd = open(full_path, O_RDWR | O_NONBLOCK);
							break;
						}
					}
				}
				fd = -1;
			}
		}
	} while (dp);

	closedir(dir);

	if (fd != -1) {
		r = read(fd, original_suspend_mode, sizeof(original_suspend_mode)-1);
		if (r > 0) {
			original_suspend_mode[r-1] = 0;
		}

	}

	return fd;
}

static void* input_loop(void* ptr) {
	int input_fd;
	struct input_event ev;
	int x, y, left, middle, right, wheel;
	int old_left, old_middle, old_right;
	struct timespec ts;
	struct libevdev* dev;
	int rc, grab, r;

	int power_control_fd;
	int mouse_suspended;

	int num_updates;
	struct timespec ts_updates;

	const char* device = (const char*)ptr;
	if (device && !strlen(device)) {
		device = NULL;
	}

	while(running) {
		if (device) {
			input_fd = open_input(device);
		} else {
			input_fd = find_input();
		}
		if (input_fd < 0) {
			printf("Waiting for mouse...\n");

			/* Sleep and try again soon */
			sleep_ms(2000);

			continue;
		}

		rc = libevdev_new_from_fd(input_fd, &dev);

		printf("Found mouse: %s (vendor: %x, product: %x)\n", libevdev_get_name(dev), libevdev_get_id_vendor(dev), libevdev_get_id_product(dev));
		grab = 1;
		printf("Exclusive mouse access: %s\n", !ioctl(input_fd, EVIOCGRAB, &grab) ? "yes" : "no");

		power_control_fd = -1;
		mouse_suspended = 0;
		if (mouse_auto_suspend) {
			power_control_fd = find_power_control(libevdev_get_id_vendor(dev), libevdev_get_id_product(dev));
			if (power_control_fd == -1) {
				printf("Suspend is not available.\n");
			} else {
				printf("Suspend enabled.\n");
			}
		}

		left = middle = right = 0;
		input_running = 1;
		x = y = 0;
		wheel = 0;
		old_left = old_middle = old_right = 0;

		if (verbose_level >= 1) {
			num_updates = 0;
			clock_now(&ts_updates);
		}

		while (running && input_running) {
			if (power_control_fd != -1) {
				if (mouse_suspend && !mouse_suspended) {
					mouse_suspended = 1;
					r = write(power_control_fd, "auto", 4*sizeof(char));
					printf("Mouse suspended.\n");
				} else if (!mouse_suspend && mouse_suspended) {
					mouse_suspended = 0;
					r = write(power_control_fd, "on", 2*sizeof(char));
					printf("Mouse resumed.\n");
				}
			}
			rc = libevdev_next_event(dev, LIBEVDEV_READ_FLAG_NORMAL, &ev);
			if (rc < 0) {
				if (rc != -EAGAIN) {
					fprintf(stderr, "Error: %d %s\n", -rc, strerror(-rc));
					input_running = 0;
				} else if (mouse_suspend) {
					sleep_ms(1);
				}
			} else if (rc == LIBEVDEV_READ_STATUS_SYNC) {
				/* This code is untested */
				while (rc == LIBEVDEV_READ_STATUS_SYNC) {
					rc = libevdev_next_event(dev, LIBEVDEV_READ_FLAG_SYNC, &ev);
					if (rc < 0) {
						if (rc != -EAGAIN) {
							fprintf(stderr, "Error %d (%s)\n", -rc, strerror(-rc));
							input_running = 0;
						}
						break;
					}
				}
			} else if (rc == LIBEVDEV_READ_STATUS_SUCCESS) {
				if (ev.type == EV_REL) {
					if (ev.code == REL_X) {
						x = ev.value;
					} else if (ev.code == REL_Y) {
						y = ev.value;
					} else if (ev.code == REL_WHEEL) {
						wheel = ev.value;
					}
				} else if (ev.type == EV_KEY) {
					if (ev.code == BTN_LEFT) {
						left = ev.value;
					} else if (ev.code == BTN_MIDDLE) {
						middle = ev.value;
					} else if (ev.code == BTN_RIGHT) {
						right = ev.value;
					}
				} else if (ev.type == EV_SYN) {
					if (verbose_level >= 1) {
						num_updates++;
					}

					/* has anything changed? */
					if (old_right != right || old_middle != middle || old_left != left || x != 0 || y != 0 || wheel != 0) {
						pthread_mutex_lock(&input_mutex);
						/* update mouse positions */
						mouse_x += x;
						mouse_y += y;

						/* update mouse wheel */
						mouse_wheel += wheel;

						/* update mouse buttons */
						if (old_right != right) {
							push_button_queue(mouse_swap ? &mouse_left : &mouse_right, right);
						}
						if (old_left != left) {
							push_button_queue(mouse_swap ? &mouse_right : &mouse_left, left);
						}
						if (old_middle != middle) {
							push_button_queue(&mouse_middle, middle);
						}
						pthread_mutex_unlock(&input_mutex);
					}
					wheel = 0;
					x = y = 0;
					old_right = right;
					old_middle = middle;
					old_left = left;
				}
			}
			if (verbose_level >= 1) {
				if (clock_elapsed(&ts_updates) >= 1000) {
					if (num_updates > 0) {
						printf("Input polling rate: %dhz\n", num_updates);
					}
					num_updates = 0;
					clock_now(&ts_updates);
				}
			}
		}
		libevdev_free(dev);
		grab = 0;
		ioctl(input_fd, EVIOCGRAB, &grab);
		close(input_fd);
		if (power_control_fd != -1) {
			r = write(power_control_fd, original_suspend_mode, strlen(original_suspend_mode)*sizeof(char));
			close(power_control_fd);
		}
	}

	return 0;
}

/*
 * Output
 *
 * These functions handle all output to serial port
 */

static void set_serial_options(int fd, int protocol) {
	struct termios options;
	tcgetattr(fd, &options);

	/* 1200 baud */
	cfsetispeed(&options, B1200);
	cfsetospeed(&options, B1200);

	/* Raw output */
	cfmakeraw(&options);
	options.c_cflag &= ~CRTSCTS;

	/* 7 or 8 bits, 1 stop bit, no parity */
	options.c_cflag &= ~PARENB;
	options.c_cflag &= ~CSTOPB;
	options.c_cflag &= ~CSIZE;
	if (protocol_has_feature(protocol, SERIAL_8N1)) {
		options.c_cflag |= CS8;
	} else {
		options.c_cflag |= CS7;
	}

	tcsetattr(fd, TCSANOW, &options);
}

static int open_serial(const char* dev) {
	int fd;

	fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd == -1) {
		char str[256];
		snprintf(str, sizeof(str)-1, "Unable to open %s", dev);
		perror(str);
		return -1;
	} else {
		fcntl(fd, F_SETFL, 0);
	}

	tcgetattr(fd, &original_termios_options);

	set_serial_options(fd, mouse_protocol);

	return fd;
}

static void* output_loop(void* ptr) {
	int i, serial_fd, status, read_bytes, count;
	struct timespec ts, ts_start, ts_end, ts_block, ts_suspended;
	struct input_event ev;
	struct mouse_button_t left, right, middle;
	int update;
	int x, y, wheel;
	int send_x, send_y;
	int initialize_request, initialize;
	uint8_t mousedat[5];
	int next_protocol;
	int bytes;
	int mouse_suspended;

	int num_updates;
	struct timespec ts_updates;

	int test_mode;
	int test_speed;
	struct mouse_button_t test_left, test_right, test_middle;

	serial_fd = *(int*)ptr;

	initialize_request = 0;
	initialize = 0;

	mouse_suspended = 0;
	clock_now(&ts_suspended);

	if (verbose_level >= 1) {
		num_updates = 0;
		clock_now(&ts_updates);
	}

	memset(&left, 0, sizeof(struct mouse_button_t));
	memset(&middle, 0, sizeof(struct mouse_button_t));
	memset(&right, 0, sizeof(struct mouse_button_t));

	ts_block.tv_sec = 0;
	ts_block.tv_nsec = output_rate;

	test_mode = 0;
	test_speed = 15;
	memset(&test_left, 0, sizeof(struct mouse_button_t));
	memset(&test_middle, 0, sizeof(struct mouse_button_t));
	memset(&test_right, 0, sizeof(struct mouse_button_t));

	while (running) {
		clock_now(&ts_start);

		bytes = 1;

		ioctl(serial_fd, TIOCMGET, &status);

		/* If DSR is not toggled the mouse is flagged as suspended */
		mouse_suspend = !(status&TIOCM_DSR);

		if (mouse_suspend && !mouse_suspended) {
			clock_now(&ts_suspended);
			mouse_suspended = 1;
		}

		if (!(status&TIOCM_DSR) || !(status&TIOCM_CTS)) {
			/* No power on DSR or CTS, initialize when we have it */
			initialize_request = 1;
		} else if (initialize_request) {
			verbose(1, "Mouse connected.\n");
			sleep_ms(14);
			pthread_mutex_lock(&input_mutex);
			poll_button_queue(&mouse_left, &left);
			poll_button_queue(&mouse_middle, &middle);
			poll_button_queue(&mouse_right, &right);
			pthread_mutex_unlock(&input_mutex);
			next_protocol = mouse_protocol;
			if (right.down && left.down) {
				next_protocol = PROTOCOL_LOGITECH;
			} else if (middle.down) {
				next_protocol = PROTOCOL_MICROSOFT_WHEEL;
			} else if (right.down) {
				next_protocol = PROTOCOL_MICROSOFT;
			} else if (left.down) {
				next_protocol = PROTOCOL_MOUSE_SYSTEMS;
			} else if (!mouse_suspend && mouse_suspended && PROTOCOL_RESET_TIMEOUT > 0 && clock_elapsed(&ts_suspended) >= PROTOCOL_RESET_TIMEOUT) {
				next_protocol = requested_protocol;
			}
			mouse_suspended = 0;

			if (next_protocol != PROTOCOL_MOUSE_SYSTEMS) {
				bytes = write_char(serial_fd, 'M');
				if (next_protocol == PROTOCOL_LOGITECH) {
					bytes += write_char(serial_fd, '3');
				} else if (next_protocol == PROTOCOL_MICROSOFT_WHEEL) {
					bytes += write_char(serial_fd, 'Z');
				}
			}
			if (protocol_has_feature(next_protocol, SERIAL_7N1) != protocol_has_feature(mouse_protocol, SERIAL_7N1) ||
				protocol_has_feature(next_protocol, SERIAL_8N1) != protocol_has_feature(mouse_protocol, SERIAL_8N1)) {
				set_serial_options(serial_fd, next_protocol);
			}
			if (next_protocol != mouse_protocol) {
				mouse_protocol = next_protocol;
				printf("Protocol changed to %s\n", get_protocol_name(mouse_protocol));
			}
			if (requested_output_rate > 0) {
				output_rate = requested_output_rate;
			} else {
				set_default_output_rate(mouse_protocol);
			}
			ts_block.tv_sec = 0;
			ts_block.tv_nsec = output_rate;

			initialize_request = 0;
		}

		/* Get the latest state of the mouse */
		update = 0;
		pthread_mutex_lock(&input_mutex);
		x = mouse_x;
		y = mouse_y;
		wheel = mouse_wheel;
		mouse_x = mouse_y = mouse_wheel = 0;

		if (output_test) {
			poll_button_queue(&mouse_left, &test_left);
			poll_button_queue(&mouse_middle, &test_middle);
			poll_button_queue(&mouse_right, &test_right);
		}

		if (pop_button_queue(&mouse_left, &left)) {
			update = 1;
		}
		if (pop_button_queue(&mouse_middle, &middle) && protocol_has_feature(mouse_protocol, THREE_BUTTONS)) {
			update = 1;
		}
		if (pop_button_queue(&mouse_right, &right)) {
			update = 1;
		}
		pthread_mutex_unlock(&input_mutex);

		if (x != 0 || y != 0 || (protocol_has_feature(mouse_protocol, MOUSE_WHEEL) && wheel != 0)) {
			update = 1;
		}

		if (output_test) {
			if (test_left.changed && test_left.down) {
				test_mode = (test_mode+1)%6;
				printf("Test mode: %d\n", test_mode);
			}
			if (wheel != 0) {
				if (test_right.down) {
					if (wheel < 0) {
						test_speed--;
					} else if (wheel > 0) {
						test_speed++;
					}
					printf("Test speed: %d\n", test_speed);
				} else {
					output_rate += pow(10, 5)*wheel;
					printf("Output rate: %f\n", output_rate/(1000.0*1000.0));
				}
			}

			memset(&left, 0, sizeof(struct mouse_button_t));
			memset(&middle, 0, sizeof(struct mouse_button_t));
			memset(&right, 0, sizeof(struct mouse_button_t));

			x = 0;
			y = 0;
			wheel = 0;

			if (test_mode == 1) {
				x = test_speed;
			} else if (test_mode == 2) {
				x = -test_speed;
			} else if (test_mode == 3) {
				y = test_speed;
			} else if (test_mode == 4) {
				y = -test_speed;
			} else if (test_mode == 5) {
				x = test_speed;
				y = -test_speed;
			}

			test_left.changed = test_middle.changed = test_right.changed = 0;

			update = test_mode > 0;
		}

		if (update) {
			if (verbose_level >= 1) {
				num_updates++;
			}
			if (enable_multiplier) {
				x = x < 0 ? floor(x*x_multiplier) : ceil(x*x_multiplier);
				y = y < 0 ? floor(y*y_multiplier) : ceil(y*y_multiplier);
			}

			x = clamp(x, -127, 127);
			y = clamp(y, -127, 127);
			wheel = clamp(wheel, -15, 15);

			verbose(2, "Write state (x: %d, y: %d, wheel: %d, left: %d (%d), middle: %d (%d), right: %d (%d))\n", x, y, wheel, left.down, left.changed, middle.down, middle.changed, right.down, right.changed);

			bytes = 0;

			tcdrain(serial_fd);
			if (mouse_protocol == PROTOCOL_MOUSE_SYSTEMS) {
				mousedat[0] = 0x80;
				if (!right.down) {
					mousedat[0] |= 0x01;
				}
				if (!middle.down) {
					mousedat[0] |= 0x02;
				}
				if (!left.down) {
					mousedat[0] |= 0x04;
				}

				mousedat[1] = x;
				mousedat[2] = -y;
				bytes += write_blocking(serial_fd, &mousedat[0], sizeof(uint8_t), &ts_block);
				bytes += write_blocking(serial_fd, &mousedat[1], sizeof(uint8_t), &ts_block);
				bytes += write_blocking(serial_fd, &mousedat[2], sizeof(uint8_t), &ts_block);

				/* Get x, y since the first bytes were written */
				pthread_mutex_lock(&input_mutex);
				x = mouse_x;
				y = mouse_y;
				mouse_x = mouse_y = 0;
				pthread_mutex_unlock(&input_mutex);

				if (output_test) {
					x = 0;
					y = 0;
				}

				if (enable_multiplier) {
					x = x < 0 ? floor(x*x_multiplier) : ceil(x*x_multiplier);
					y = y < 0 ? floor(y*y_multiplier) : ceil(y*y_multiplier);
				}

				x = clamp(x, -127, 127);
				y = clamp(y, -127, 127);

				mousedat[3] = x;
				mousedat[4] = -y;

				verbose(2, "Write state (x: %d, y: %d)\n", x, y);

				bytes += write_blocking(serial_fd, &mousedat[3], sizeof(uint8_t), &ts_block);
				bytes += write_blocking(serial_fd, &mousedat[4], sizeof(uint8_t), &ts_block);
			} else {
				mousedat[0] = 0x40|(((y>>6)&0x3)<<2)|((x>>6)&0x3);
				if (right.down) {
					mousedat[0] |= 0x10;
				}
				if (left.down)  {
					mousedat[0] |= 0x20;
				}
				mousedat[1] = x&0x3F;
				mousedat[2] = y&0x3F;

				bytes += write_blocking(serial_fd, &mousedat[0], sizeof(uint8_t), &ts_block);
				bytes += write_blocking(serial_fd, &mousedat[1], sizeof(uint8_t), &ts_block);
				bytes += write_blocking(serial_fd, &mousedat[2], sizeof(uint8_t), &ts_block);

				if (mouse_protocol == PROTOCOL_MICROSOFT_WHEEL) {
					mousedat[3] = -wheel&0x0f;
					if (middle.down) {
						mousedat[3] |= 0x10;
					}
					bytes += write_blocking(serial_fd, &mousedat[3], sizeof(uint8_t), &ts_block);
				} else if (mouse_protocol == PROTOCOL_LOGITECH) {
					mousedat[3] = 0;
					if (middle.down) {
						mousedat[3] |= 0x20;
					}
					if (middle.down || middle.changed) {
						bytes += write_blocking(serial_fd, &mousedat[3], sizeof(uint8_t), &ts_block);
					}
				}
			}

			left.changed = middle.changed = right.changed = 0;
		}

		if (verbose_level >= 1) {
			if (clock_elapsed(&ts_updates) >= 1000) {
				if (num_updates > 0) {
					printf("Output polling rate: %dhz\n", num_updates);
				}
				num_updates = 0;
				clock_now(&ts_updates);
			}
		}

		clock_now(&ts_end);
		clock_diff(&ts_start, &ts_end, &ts);
		ts_start.tv_sec = 0;
		ts_start.tv_nsec = bytes*output_rate;
		clock_diff(&ts, &ts_start, &ts_end);

		nanosleep(&ts_end, NULL);
	}

	return 0;
}

/*
 * Main
 */

int main(int argc, char** argv) {
	char input_device[256], output_device[256], protocol[256];
	pthread_t input_thread;
	pthread_t output_thread;
	int background;
	int serial_fd;

	double rate;
	int c, err, help;
	static const struct option long_options[] = {
		{ "version", no_argument, 0, 'V' },
		{ "help", no_argument, 0, 'h' },
		{ "verbose", no_argument, 0, 'v' },
		{ "daemon", no_argument, 0, 'd' },
		{ "suspend", no_argument, 0, 's' },
		{ "test", no_argument, 0, 't' },
		{ "swap", no_argument, 0, 'S' },

		{ "input", required_argument, 0, 'i' },
		{ "output", required_argument, 0, 'o' },
		{ "rate", required_argument, 0, 'r' },
		{ "protocol", required_argument, 0, 'p' },
		{ 0, 0, 0, 0 }
	};

	setlocale(LC_CTYPE, "");

	protocol[0] = 0;
	input_device[0] = 0;
	output_device[0] = 0;
	background = 0;
	rate = -1;
	help = 0;
	err = 0;

	while ((c = getopt_long(argc, argv, "VhvdstSi:o:r:p:x:y:", long_options, NULL)) != EOF) {
		switch (c) {
		case 'V':
			printf("USB Mouse to Serial 1.0\n");
			return EXIT_SUCCESS;

		case 'v':
			verbose_level++;
			break;

		case 'h':
			help = 1;
			break;

		case 'd':
			background = 1;
			break;

		case 's':
			mouse_auto_suspend = 1;
			break;

		case 't':
			output_test = 1;
			break;

		case 'S':
			mouse_swap = 1;
			break;

		case 'i':
			snprintf(input_device, sizeof(input_device)-1, "%s", optarg);
			break;

		case 'o':
			snprintf(output_device, sizeof(output_device)-1, "%s", optarg);
			break;

		case 'r':
			rate = atof(optarg);
			break;

		case 'p':
			snprintf(protocol, sizeof(protocol)-1, "%s", optarg);
			break;

		case 'x':
			x_multiplier = atof(optarg);
			enable_multiplier = 1;
			break;

		case 'y':
			y_multiplier = atof(optarg);
			enable_multiplier = 1;
			break;

		case '?':
		default:
			err++;
			break;
		}
	}

	if (err || argc > optind || help) {
		fprintf(stderr, "Usage: usb_mouse_to_serial [options]...\n"
			"Translates USB mouse input to serial port\n"
			"  -o, --output device\n"
			"      Serial device to use as output\n"
			"  -i, --input device\n"
			"      USB mouse device to use as input, if not set it\n"
			"      will attempt to find one automatically\n"
			"  -p, --protocol protocol\n"
			"      The serial mouse protocol to use, one of\n"
			"      microsoft, logitech, wheel or mousesystems\n"
			"  -r, --rate rate\n"
			"      The rate to write to serial output device\n"
			"      in milliseconds\n"
			"  -d, --daemon\n"
			"      Run in background\n"
			"  -s, --suspend\n"
			"      Automatically suspend mouse when there is no\n"
			"      power from the serial port\n"
			"  -x multiplier\n"
			"      Multiply X with this value\n"
			"  -y multiplier\n"
			"      Multiply Y with this value\n"
			"  -S, --swap\n"
			"      Swap left and right mouse buttons\n"
			"  -v, --verbose\n"
			"      Increase verbosity, can be used multiple times\n"
//			"  -t, --test\n"
//			"      Enable output test mode\n"
			"  -V, --version\n"
			"      Show version\n"
			"  -h, --help\n"
			"      Show usage and help\n"
			);
		return EXIT_FAILURE;
	}

	requested_protocol = PROTOCOL_MICROSOFT;
	if (strlen(protocol)) {
		if (tolower(protocol[0]) == 'l') { /* Logitech 3-button mouse */
			requested_protocol = PROTOCOL_LOGITECH;
		} else if (tolower(protocol[0]) == 'w' || !strcasecmp(protocol, "microsoftw")) { /* Microsoft 3-button wheel mouse */
			requested_protocol = PROTOCOL_MICROSOFT_WHEEL;
		} else if (!strcasecmp(protocol, "mousesystems")) { /* Mouse Systems */
			requested_protocol = PROTOCOL_MOUSE_SYSTEMS;
		}
	}
	mouse_protocol = requested_protocol;
	printf("Protocol: %s\n", get_protocol_name(mouse_protocol));

	if (enable_multiplier) {
		printf("X/Y multiplier: %.1f, %.1f\n", x_multiplier, y_multiplier);
	}

	if (rate < 0) {
		requested_output_rate = 0;
	} else {
		requested_output_rate = rate*1000.0*1000.0;
	}
	requested_output_rate = clamp(requested_output_rate, 0, 100*1000*1000);

	if (requested_output_rate > 0) {
		output_rate = requested_output_rate;
		printf("Requested output rate: %.1f ms\n", requested_output_rate/(1000.0*1000.0));
	} else {
		printf("Default output rate.\n");
		set_default_output_rate(mouse_protocol);
	}
	if (mouse_swap) {
		printf("Left and right mouse buttons swapped.\n");
	}
	if (verbose_level > 0) {
		printf("Verbose level: %d\n", verbose_level);
	}

	if (output_device && !strlen(output_device)) {
		snprintf(output_device, sizeof(output_device)-1, "/dev/ttyUSB0");
	}

	printf("Opening serial device %s...\n", output_device);
	serial_fd = open_serial(output_device);

	if (serial_fd == -1) {
		return EXIT_FAILURE;
	}

	if (output_test) {
		background = mouse_auto_suspend = 0;
	}

	running = 1;

	signal(SIGINT, inthandler);
	signal(SIGTERM, inthandler);

	if (background) {
		printf("Running in background (PID: %d)\n", getpid()+1);
		err = daemon(0, 0);
	}

	memset(&mouse_left, 0, sizeof(struct mouse_button_queue_t));
	memset(&mouse_middle, 0, sizeof(struct mouse_button_queue_t));
	memset(&mouse_right, 0, sizeof(struct mouse_button_queue_t));

	pthread_mutex_init(&input_mutex, NULL);
	pthread_create(&input_thread, NULL, input_loop, input_device);
	pthread_create(&output_thread, NULL, output_loop, &serial_fd);

	pthread_join(output_thread, NULL);
	running = 0;
	input_running = 0;
	pthread_join(input_thread, NULL);

	/* Reset serial port to its original options */
	tcsetattr(serial_fd, TCSANOW, &original_termios_options);
	close(serial_fd);
	
	if (output_test) {
		printf("Output rate: %f\n", (output_rate/(1000.0*1000.0)));
	}

	return EXIT_SUCCESS;
}
