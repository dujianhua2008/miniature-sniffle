// @ts-忽略
从‘cloudflare:sockets’导入{connect}；

// 如何生成您自己的 UUID：
// [Windows] 按“Win + R”，输入 cmd 并运行：Powershell -NoExit -Command "[guid]::NewGuid()"
让用户ID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

const พร็อกซีไอพีs = ['cdn.xn--b6gac.eu.org', 'cdn-all.xn--b6gac.eu.org', 'workers.cloudflare.cyou'];

// 如果您想使用 ipv6 或单播地址，请在此行添加注释并在下一行删除注释
让 พร็อกซีไอพี = พร็อกซีไอพีs[Math.floor(Math.random() * พร็อกซีไอพีs.length)];
// 使用单个 พร็อกซีไอพี 而不是随机
// 让พร็อกซีไอพี = 'cdn.xn--b6gac.eu.org';
// ipv6 พร็อกซีไอพี示例删除注释以使用
// 让พร็อกซีไอพี = "[2a01:4f8:c2c:123f:64:5:6810:c55a]"

let dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg='; // https://cloudflare-dns.com/dns-query 或 https://dns.google/dns-query

如果（！isValidUUID（用户ID））{
	抛出新的错误（'uuid无效'）；
}

导出默认值 {
	/**
	 * @param {import("@cloudflare/workers-types").Request} 请求
	 * @param {{UUID：字符串，พร็อกซีไอพี：字符串，DNS_RESOLVER_URL：字符串，NODE_ID：int，API_HOST：字符串，API_TOKEN：字符串}} env
	 * @param {导入（“@cloudflare/workers-types”）。ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	异步获取（请求，环境，ctx）{
		// uuid_validator（请求）；
		尝试 {
			用户ID = 环境.UUID || 用户ID;
			พร็อกซีไอพี = env.PROXYIP || พร็อกซีไอพี;
			dohURL = 环境.DNS_RESOLVER_URL || dohURL;
			让用户ID_Path = 用户ID；
			如果（用户ID.包括（'，'））{
				用户ID_Path = 用户ID.split('，')[0];
			}
			const UpgradeHeader = request.headers.get('升级');
			如果（！upgradeHeader ||upgradeHeader！=='websocket'）{
				const url = new URL(请求.url);
				开关（url.路径名）{
					案例`/cf`：{
						返回新的响应（JSON.stringify（request.cf，null，4），{
							状态：200，
							标题：{
								“内容类型”：“application/json;charset=utf-8”，
							}，
						});
					}
					案例 `/${userID_Path}`: {
						const วเลสConfig = getวเลสConfig(userID, request.headers.get('Host'));
						返回新的响应(`${วเลสConfig}`, {
							状态：200，
							标题：{
								“内容类型”：“text/html; charset=utf-8”，
							}
						});
					};
					案例`/sub/${userID_Path}`：{
						const url = new URL(请求.url);
						const searchParams = url.searchParams;
						const วเลสSubConfig = สร้างวเลสSub(userID, request.headers.get('Host'));
						// 构造并返回响应对象
						返回新的响应（btoa（วเลสSubConfig），{
							状态：200，
							标题：{
								“内容类型”：“text/plain；charset=utf-8”，
							}
						});
					};
					案例`/bestip/${userID_Path}`：{
						const headers = 请求.headers;
						const url = `https://sub.xf.free.hr/auto?host=${request.headers.get('Host')}&uuid=${userID}&path=/`;
						const bestSubConfig = await fetch(url，{ headers：headers });
						返回 bestSubConfig；
					};
					默认：
						// 返回新的 Response('未找到', { status: 404 });
						// 对于任何其他路径，反向代理到“随机网站”并返回原始响应，并在过程中缓存它
						const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
						const newHeaders = new Headers(request.headers);
						newHeaders.set（'cf-connecting-ip'，'1.2.3.4'）;
						newHeaders.set（'x-forwarded-for'，'1.2.3.4'）;
						newHeaders.set（'x-real-ip'，'1.2.3.4'）;
						newHeaders.set('referer', 'https://www.google.com/search?q=edtunnel');
						// 使用 fetch 将请求代理到 15 个不同的域
						const proxyUrl = 'https://' + randomHostname + url.pathname + url.search;
						让modifiedRequest = new Request（proxyUrl，{
							方法：request.method，
							标题：newHeaders，
							主体：请求主体，
							重定向：“手动”，
						});
						const proxyResponse = await fetch(modifiedRequest，{redirect：'manual'});
						// 检查 302 或 301 重定向状态并返回错误响应
						如果（[301，302].包括（proxyResponse.status））{
							返回新的响应（`不允许重定向到${randomHostname}。`，{
								状态：403，
								状态文本：‘禁止’，
							});
						}
						// 返回代理服务器的响应
						返回代理响应；
				}
			} 别的 {
				返回 await วเลสOverWSHandler(request);
			}
		} 捕获 (错误) {
			/** @type {Error} */ let e = err;
			返回新的Response（e.toString（））；
		}
	}，
};

导出异步函数 uuid_validator（请求）{
	const hostname = request.headers.get('主机名');
	const currentDate = new Date();

	const 子域名 = 主机名.split('.')[0];
	const year = currentDate.getFullYear();
	const month = String(currentDate.getMonth() + 1).padStart(2, '0');
	const day = String(currentDate.getDate()).padStart(2，'0');

	const formattedDate = `${year}-${month}-${day}`;

	// const daliy_sub = formattedDate + 子域
	const hashHex = await hashHex_f(子域);
	// 子域字符串包含时间戳 utc 和 uuid 字符串 TODO。
	console.log（hashHex，子域名，formattedDate）；
}

导出异步函数 hashHex_f（字符串）{
	const 编码器 = new TextEncoder();
	const 数据 = 编码器.编码（字符串）;
	const hashBuffer = await crypto.subtle.digest('SHA-256', 数据);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(byte => byte.toString(16).padStart(2，'0')).join('');
	返回 hashHex；
}

/**
 * 通过创建 WebSocket 对、接受 WebSocket 连接和处理 วเลส 标头来处理 WebSocket 上的 วเลส 请求。
 * @param {import("@cloudflare/workers-types").Request} request 传入的请求对象。
 * @returns {Promise<Response>} 解析为 WebSocket 响应对象的 Promise。
 */
异步函数 OverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [客户端， webSocket] = Object.values(webSocketPair);
	webSocket.accept()；

	让地址=''；
	让 portWithRandomLog = '';
	让 currentDate = new Date();
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, 事件 || '');
	};
	const earlyDataHeader = 请求.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ 值：导入（“@cloudflare/workers-types”）。Socket | null}} */
	让 remoteSocketWapper = {
		值：null，
	};
	让 udpStreamWrite = null;
	让 isDns = false;

	// ws --> 远程
	readableWebSocketStream.pipeTo(new WritableStream({
		异步写入（块，控制器）{
			如果（isDns && udpStreamWrite）{
				返回 udpStreamWrite(chunk);
			}
			如果（remoteSocketWapper.值）{
				const writer = remoteSocketWapper.value.writable.getWriter()
				等待 writer.write(chunk);
				释放锁
				返回;
			}

			常量 {
				有错误，
				信息，
				远程端口 = 443，
				远程地址 = '',
				原始数据索引，
				版本 = new Uint8Array([0, 0]),
				是UDP，
			} = processวเลสHeader(chunk, userID);
			地址=地址远程；
			portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
			如果（有错误）{
				// 控制器.错误（消息）；
				抛出新的错误（消息）；// cf 似乎有错误，controller.error 不会结束流
			}

			// 如果是 UDP 端口而非 DNS 端口，则关闭它
			if (isUDP && portRemote !== 53) {
				抛出新的错误（'UDP代理仅为端口53的DNS启用'）;
				// cf 似乎有 bug，controller.error 不会结束流
			}

			if (isUDP && portRemote === 53) {
				isDns = true;
			}

			// ["version", "附加信息长度N"]
			const วเลสResponseHeader = new Uint8Array([วเลสVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			// TODO：当 cf 运行时支持 udp 时，在此处支持 udp
			如果（isDns）{
				const { write } = await handleUDPOutBound(webSocket， HttpResponseHeader， log);
				udpStreamWrite = 写入；
				udpStreamWrite（原始客户端数据）；
				返回;
			}
			handleTCPOutBound（remoteSocketWapper，addressRemote，portRemote，rawClientData，webSocket，วเลสResponseHeader，log）;
		}，
		关闭（） {
			log(`readableWebSocketStream 已关闭`);
		}，
		中止（原因）{
			log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
		}，
	})).catch((err) => {
		log('readableWebSocketStream pipeTo 错误', err);
	});

	返回新的响应（null，{
		状态：101，
		webSocket：客户端，
	});
}

/**
 * 处理出站 TCP 连接。
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote 要连接的远程地址。
 * @param {number} portRemote 要连接的远程端口。
 * @param {Uint8Array} rawClientData 要写入的原始客户端数据。
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 将远程套接字传递给的 WebSocket。
 * @param {Uint8Array} วเลสResponseHeader วเลส响应标头。
 * @param {function} log 日志记录功能。
 * @returns {Promise<void>} 远程套接字。
 */
异步函数 handleTCPOutBound(remoteSocket、addressRemote、portRemote、rawClientData、webSocket、ResponseHeader、log) {

	/**
	 * 连接到给定的地址和端口并将数据写入套接字。
	 * @param {string} address 要连接的地址。
	 * @param {number} port 要连接的端口。
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} 解析为已连接套接字的 Promise。
	 */
	异步函数 connectAndWrite（地址，端口）{
		/** @type {导入（“@cloudflare/workers-types”）。Socket} */
		const tcpSocket = connect({
			主机名：地址，
			港口：港口，
		});
		remoteSocket.value = tcpSocket;
		log(`连接到 ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); // 第一次写入，正常是 tls client hello
		释放锁
		返回 tcpSocket；
	}

	/**
	 * 如果 Cloudflare 套接字没有传入数据，则重试连接到远程地址和端口。
	 * @returns {Promise<void>} 重试完成时解析的 Promise。
	 */
	异步函数重试（）{
		const tcpSocket =等待connectAndWrite(พร็อกซีไอพี || addressRemote, portRemote)
		tcpSocket.closed.catch（错误=> {
			console.log('重试 tcpSocket 关闭错误', error);
		}).最后（（）=> {
			安全关闭WebSocket（webSocket）；
		})
		remoteSocketToWS（tcpSocket，webSocket，HTTPResponseHeader，null，log）;
	}

	const tcpSocket = await connectAndWrite(addressRemote，portRemote);

	// 当 remoteSocket 准备就绪时，传递给 websocket
	// 远程--> ws
	remoteSocketToWS（tcpSocket，webSocket，HTTPResponseHeader，重试，日志）；
}

/**
 * 从 WebSocket 服务器创建可读流，允许从 WebSocket 读取数据。
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer 用于创建可读流的 WebSocket 服务器。
 * @param {string} earlyDataHeader 包含 WebSocket 0-RTT 的早期数据的标头。
 * @param {(info: string)=> void} log 日志记录功能。
 * @returns {ReadableStream} 可用于从 WebSocket 读取数据的可读流。
 */
函数 makeReadableWebSocketStream（webSocketServer，earlyDataHeader，log）{
	让 readableStreamCancel = false;
	const stream = new ReadableStream({
		启动（控制器）{
			webSocketServer.addEventListener('消息', (事件) => {
				const 消息 = 事件.数据;
				控制器.入队（消息）；
			});

			webSocketServer.addEventListener('关闭', () => {
				安全关闭WebSocket（webSocket服务器）；
				控制器.关闭（）；
			});

			webSocketServer.addEventListener('错误', (err) => {
				log('webSocketServer 发生错误');
				控制器.错误（错误）；
			});
			const { earlyData，error } = base64ToArrayBuffer(earlyDataHeader);
			如果（错误）{
				控制器.错误（错误）；
			}否则，如果（早期数据）{
				控制器.入队（早期数据）；
			}
		}，

		拉（控制器）{
			// 如果 ws 可以在流已满时停止读取，我们就可以实现背压
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		}，

		取消（原因）{
			log(`ReadableStream 被取消，原因是 ${reason}`)
			可读流取消 = 真；
			安全关闭WebSocket（webSocket服务器）；
		}
	});

	返回流；
}

// https://xtls.github.io/development/protocols/วเลส.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * 处理 วเลส 头缓冲区并返回包含相关信息的对象。
 * @param {ArrayBuffer} Buffer 要处理的头缓冲区。
 * @param {string} userID 用于根据 วเลส 标头中的 UUID 进行验证的用户 ID。
 * @returns {{
 * hasError：布尔值，
 * 消息？：字符串，
 * addressRemote?: 字符串，
 * 地址类型？: 数字,
 * portRemote?: 号码,
 * rawDataIndex?: 数字,
 *版本？：Uint8Array，
 * 是UDP吗？：布尔值
 * }} 从 วเลส 头缓冲区中提取相关信息的对象。
 */
function processวเลสHeader(วเลสBuffer, userID) {
	if (วเลสBuffer.byteLength < 24) {
		返回 {
			hasError: true,
			消息：“无效数据”，
		};
	}

	const version = new Uint8Array(วเลสBuffer.slice(0, 1));
	让 isValidUser = false;
	让 isUDP = false;
	const slicedBuffer = new Uint8Array(วเลสBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);
	// 检查 userID 是否为有效的 uuid 或按 拆分的 uuids，并且包含 userID，否则将错误消息返回到控制台
	const uuids = userID.includes(',') ? userID.split(",") : [userID];
	// uuid_validator（主机名，slicedBufferString）；


	// isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim());
	isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();

	console.log(`用户ID: ${slicedBufferString}`);

	如果（！isValidUser）{
		返回 {
			hasError: true,
			消息：“无效用户”，
		};
	}

	const optLength = new Uint8Array(วเลสBuffer.slice(17, 18))[0];
	//暂时跳过 opt

	const 命令 = new Uint8Array(
		复制Buffer.slice(18 + optLength, 18 + optLength + 1)
	)(0]；

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 多路复用器
	如果（命令 === 1）{
		是UDP = false;
	} 否则，如果（命令 === 2）{
		是UDP =真；
	} 别的 {
		返回 {
			hasError: true,
			消息：`命令 ${command} 不受支持，命令 01-tcp,02-udp,03-mux`，
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = 端口Buffer.slice(portIndex, portIndex + 2);
	// 端口在原始数据等中是大端的 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	让地址索引 = 端口索引 + 2；
	const addressBuffer = new Uint8Array(
		复制Buffer.slice(addressIndex, addressIndex + 1)
	（此处似有缺失，请提供更正后的文本）。

	// 1--> ipv4 地址长度 =4
	// 2-->域名addressLength=addressBuffer[1]
	// 3--> ipv6 地址长度 =16
	const addressType = addressBuffer[0];
	让地址长度 = 0;
	让 addressValueIndex = addressIndex + 1;
	让地址值 = '';
	开关（地址类型）{
		情况 1：
			地址长度 = 4;
			地址值 = 新的 Uint8Array(
				块Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
			）。加入（'。'）;
			休息;
		情况 2：
			地址长度 = 新的 Uint8Array(
				复制Buffer.slice(addressValueIndex, addressValueIndex + 1)
			)(0]；
			地址值索引 += 1;
			addressValue = new TextDecoder().解码(
				块Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
			（此处似有缺失，请提供更正后的文本）。
			休息;
		情况 3：
			地址长度=16；
			const dataView = new DataView(
				块Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
			（此处似有缺失，请提供更正后的文本）。
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			对于（设 i = 0；i < 8；i++）{
				ipv6.推送（dataView.getUint16（i * 2).toString（16））；
			}
			地址值 = ipv6.join(':');
			// 似乎不需要为 ipv6 添加 []
			休息;
		默认：
			返回 {
				hasError: true,
				消息：`invild addressType 是 ${addressType}`，
			};
	}
	如果（！地址值）{
		返回 {
			hasError: true,
			消息：`addressValue 为空，addressType 为 ${addressType}`，
		};
	}

	返回 {
		hasError: false,
		addressRemote: 地址值，
		地址类型，
		远程端口，
		原始数据索引:地址值索引+地址长度，
		วเลสVersion：版本，
		是UDP，
	};
}


/**
 * 将远程套接字转换为 WebSocket 连接。
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket 要转换的远程套接字。
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 要连接的 WebSocket。
 * @param {ArrayBuffer | null} วเลสResponseHeader วเลส响应标头。
 * @param {(() => Promise<void>) | null} retry 如果连接失败则重试的函数。
 * @param {(info: string) => void} log 日志记录功能。
 * @returns {Promise<void>} 转换完成时解析的 Promise。
 */
异步函数 remoteSocketToWS（remoteSocket、webSocket、ResponseHeader、重试、日志）{
	// 远程--> ws
	让 remoteChunkCount = 0;
	让块= []；
	/** @type {ArrayBuffer | null} */
	让วเลสHeader = วเลสResponseHeader;
	let hasIncomingData = false; // 检查 remoteSocket 是否有传入数据
	等待 remoteSocket.readable
		.pipeTo（
			新的WritableStream（{
				开始（） {
				}，
				/**
				 *
				 * @param {Uint8Array} 块
				 * @param {*} 控制器
				 */
				异步写入（块，控制器）{
					hasIncomingData = true;
					远程块计数++；
					如果（webSocket.readyState！== WS_READY_STATE_OPEN）{
						控制器.错误（
							'webSocket.readyState 未打开，可能已关闭'
						（此处似有缺失，请提供更正后的文本）。
					}
					if (วเลสHeader) {
						webSocket.send(await new Blob([วเลสHeader，chunk]).arrayBuffer());
						วเลสHeader = null;
					} 别的 {
						// console.log(`remoteSocketToWS 发送块 ${chunk.byteLength}`);
						// 似乎不需要对此进行速率限制，CF 似乎修复了这个问题？？..
						// 如果 (remoteChunkCount > 20000) {
						// // 假设一个包是 4096 字节（4kb），4096 * 20000 = 80M
						//等待延迟（1）；
						// }
						webSocket.发送（块）；
					}
				}，
				关闭（） {
					log(`remoteConnection!.readable 已关闭，hasIncomingData 为 ${hasIncomingData}`);
					// safeCloseWebSocket(webSocket); // 不需要服务器先关闭 websocket，因为某些情况下会导致 HTTP ERR_CONTENT_LENGTH_MISMATCH 问题，客户端无论如何都会发送关闭事件。
				}，
				中止（原因）{
					console.error(`remoteConnection!.readable abort`, reason);
				}，
			})
		)
		.catch((错误) => {
			控制台.错误（
				`remoteSocketToWS 发生异常`，
				错误.堆栈 || 错误
			（此处似有缺失，请提供更正后的文本）。
			安全关闭WebSocket（webSocket）；
		});

	// 似乎是 cf 连接套接字有错误，
	// 1. Socket.closed 会报错
	// 2. Socket.readable 将会关闭，没有任何数据到来
	如果（hasIncomingData === false && 重试）{
		日志（`重试`）
		重试（）；
	}
}

/**
 * 将 base64 字符串解码为 ArrayBuffer。
 * @param {string} base64Str 要解码的 base64 字符串。
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}} 一个包含已解码 ArrayBuffer 的对象，如果出现错误则返回 null，如果解码期间没有错误则返回 null。
 */
函数 base64ToArrayBuffer(base64Str) {
	如果（！base64Str）{
		返回 { earlyData: null, error: null };
	}
	尝试 {
		// 使用修改后的 Base64 编码 URL rfc4648，但 js atob 不支持
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const 解码 = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		返回 { earlyData：arryBuffer.buffer，错误：null }；
	} 捕获（错误）{
		返回 { earlyData: null, error };
	}
}

/**
 * 检查给定的字符串是否是有效的 UUID。
 * 注意：这不是真正的 UUID 验证。
 * @param {string} uuid 要验证为 UUID 的字符串。
 * @returns {boolean} 如果字符串是有效的 UUID，则返回 True，否则返回 false。
 */
函数 isValidUUID（uuid）{
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	返回 uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * 安全地关闭 WebSocket 连接而不引发异常。
 * @param {import("@cloudflare/workers-types").WebSocket} socket 要关闭的 WebSocket 连接。
 */
函数 safeCloseWebSocket(socket) {
	尝试 {
		如果（socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING）{
			套接字.关闭()；
		}
	} 捕获（错误）{
		console.error('safeCloseWebSocket 错误', error);
	}
}

const byteToHex = [];

对于（设 i = 0；i < 256；++i）{
	byteToHex.push((i + 256).toString(16).slice(1));
}

函数 unsafeStringify(arr，offset = 0) {
	返回（byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

函数 stringify(arr，offset = 0) {
	const uuid = unsafeStringify(arr，偏移量);
	如果（！isValidUUID（uuid））{
		抛出 TypeError(“字符串化的 UUID 无效”);
	}
	返回 uuid；
}


/**
 * 通过将数据转换为 DNS 查询并通过 WebSocket 连接发送来处理出站 UDP 流量。
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 用于发送 DNS 查询的 WebSocket 连接。
 * @param {ArrayBuffer} วเลสResponseHeader วเลส响应头。
 * @param {(string) => void} log 日志记录功能。
 * @returns {{write: (chunk: Uint8Array) => void}} 一个具有写入方法的对象，它接受一个 Uint8Array 块来写入转换流。
 */
异步函数 handleUDPOutBound(webSocket，ResponseHeader，log) {

	让 isวเลสHeaderSent = false;
	const transformStream = new TransformStream({
		启动（控制器）{

		}，
		变换（块，控制器）{
			// udp 消息 2 字节是 udp 数据的长度
			// TODO：这应该有 bug，因为 udp 块可能在两个 websocket 消息中
			对于（让索引 = 0；索引 < chunk.byteLength；）{
				const lengthBuffer = chunk.slice(index，index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(索引 + 2，索引 + 2 + udpPakcetLength)
				（此处似有缺失，请提供更正后的文本）。
				索引 = 索引 + 2 + udpPakcetLength；
				控制器.入队（udpData）；
			}
		}，
		冲洗（控制器）{
		}
	});

	// 目前仅处理 dns udp
	transformStream.readable.pipeTo(new WritableStream({
		异步写入（块）{
			const resp = await fetch(dohURL, // DNS 服务器 URL
				{
					方法：'POST'，
					标题：{
						‘内容类型’：‘应用程序/dns消息’，
					}，
					主体：块，
				})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			// console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			如果 (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh 成功且 dns 消息长度为 ${udpSize}`);
				if (isวเลสHeaderSent) {
					webSocket.send（等待新的Blob（[udpSizeBuffer，dnsQueryResult]）。arrayBuffer（））;
				} 别的 {
					webSocket.send(await new Blob([ResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isวเลสHeaderSent = true;
				}
			}
		}
	})).catch((错误) => {
		log(‘dns udp 有错误’ + error)
	});

	const writer = transformStream.writable.getWriter();

	返回 {
		/**
		 *
		 * @param {Uint8Array} 块
		 */
		写入（块）{
			writer.写入（块）；
		}
	};
}

const at = 'QA==';
const pt = 'dmxlc3M=';
const ed = 'RUR0dW5uZWw=';
/**
 *
 * @param {string} userID - 单个或逗号分隔的用户 ID
 * @param {string | null} 主机名
 * @returns {字符串}
 */
function getวเลสConfig(userIDs, hostName) {
	const commonUrlPart = `：443？加密=无&安全性=tls&sni=${hostName}&fp=随机&类型=ws&主机=${hostName}&路径=％2F％3Fed％3D2048#${hostName}`；
	const hashSeparator = "########################################################################";

	// 将用户ID拆分成数组
	const userIDArray = userIDs.split("，");

	// 为每个用户 ID 准备输出字符串
	const 输出 = userIDArray.map((userID) => {
		const วเลสMain = atob(pt) + '://' + userID + atob(at) + 主机名 + commonUrlPart;
		const วเลสSec = atob(pt) + '://' + userID + atob(at) + พร็อกซีไอพี + commonUrlPart;
		返回 `<h2>UUID: ${userID}</h2>${hashSeparator}\nv2ray 默认 ip
----------------------------------------------------------------
${วเลสMain}
<button onclick='copyToClipboard("${วเลสMain}")'><i class="fa fa-clipboard"></i> 复制วเลสMain</button>
----------------------------------------------------------------
v2ray 与 bestip
----------------------------------------------------------------
${วเลสSec}
<button onclick='copyToClipboard("${วเลสSec}")'><i class="fa fa-clipboard"></i> 复制วเลสSec</button>
---------------------------------------------------------------`;
	}).加入('\n');
	const sublink = `https://${hostName}/sub/${userIDArray[0]}?format=clash`
	const subbestip = `https://${hostName}/bestip/${userIDArray[0]}`;
	const clash_link = `https://api.v1.mk/sub?target=clash&url=${encodeURIComponent(sublink)}&insert=false&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
	// 准备标题字符串
	const 标头 = `
<palign='center'><img src='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' alt='图片描述' style='margin-bottom: -50px;'>
<b style='font-size: 15px;'>欢迎使用！此函数用于生成 วเลส 协议的配置。如果您觉得此函数有用，请查看我们的 GitHub 项目了解更多信息：</b>
<b style='font-size: 15px;'>欢迎！这是生成วเลส协议的配置。如果您发现这个项目很好用，请查看我们的 GitHub 项目给我一个star：</b>
<a href='https://github.com/3Kmfi6HP/EDtunnel' target='_blank'>EDtunnel - https://github.com/3Kmfi6HP/EDtunnel</a>
<iframe src='https://ghbtns.com/github-btn.html?user=USERNAME&repo=REPOSITORY&type=star&count=true&size=large' frameborder='0' scrolling='0' width='170' height='30' title='GitHub'></iframe>
<a href='//${hostName}/sub/${userIDArray[0]}' target='_blank'>วเลส 节点订阅连接</a>
<a href='clash://install-config?url=${encodeURIComponent(`https://${hostName}/sub/${userIDArray[0]}?format=clash`)}}' target='_blank'>Clash for Windows 节点订阅连接</a>
<a href='${clash_link}' target='_blank'>Clash 节点订阅连接</a>
<a href='${subbestip}' target='_blank'>优选IP自动节点订阅</a>
<a href='clash://install-config?url=${encodeURIComponent(subbestip)}' target='_blank'>Clash优选IP自动</a>
<a href='sing-box://import-remote-profile?url=${encodeURIComponent(subbestip)}' target='_blank'>singbox优选IP自动</a>
<a href='sn://subscription?url=${encodeURIComponent(subbestip)}' target='_blank'>nekobox优选IP自动</a>
<a href='v2rayng://install-config?url=${encodeURIComponent(subbestip)}' target='_blank'>v2rayNG优选IP自动</a></p>`;

	// 带有 CSS 和 FontAwesome 库的 HTML Head
	const htmlHead = `
  <head>
	<title>EDtunnel：配置</title>
	<meta name='description' content='这是一个用于生成 วเลส 协议配置的工具。如果您觉得它有用，请在 GitHub https://github.com/3Kmfi6HP/EDtunnel 上给我们一个 star！'>
	<meta name='keywords' content='EDtunnel、cloudflare pages、cloudflare worker、severless'>
	<meta name='viewport' content='width=device-width, initial-scale=1'>
	<meta property='og:site_name' content='EDtunnel:วเลส配置'/>
	<meta property='og:type' content='网站' />
	<meta property='og:title' content='EDtunnel - วเลส 配置和订阅输出' />
	<meta property='og:description' content='使用 cloudflare pages 和 worker serverless 实现 วเลส 协议' />
	<meta property='og:url' content='https://${hostName}/' />
	<meta property='og:image' content='https://api.qrserver.com/v1/create-qr-code/?size=500x500&data=${encodeURIComponent(`วเลส://${userIDs.split(",")[0]}@${hostName}${commonUrlPart}`)}' />
	<meta name='twitter:card' content='summary_large_image' />
	<meta name='twitter:title' content='EDtunnel - วเลส 配置和订阅输出' />
	<meta name='twitter:description' content='使用 cloudflare pages 和 worker serverless 实现 วเลส 协议' />
	<meta name='twitter:url' content='https://${hostName}/' />
	<meta name='twitter:image' content='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' />
	<meta property='og:image:width' content='1500' />
	<meta property='og:image:height' content='1500' />

	<样式>
	身体 {
	  字体系列：Arial，无衬线；
	  背景颜色：#f0f0f0；
	  颜色：#333；
	  填充：10px；
	}

	一个{
	  颜色：#1a0dab；
	  文字修饰：无；
	}
	图片 {
	  最大宽度：100%；
	  高度：自动；
	}

	前 {
	  空白：预先包装；
	  自动换行：break-word；
	  背景颜色：#fff；
	  边框：1px 实线 #ddd；
	  填充：15px；
	  边距：10px 0；
	}
	/* 暗黑模式 */
	@media（首选配色方案：深色）{
	  身体 {
		背景颜色：#333；
		颜色：#f0f0f0；
	  }

	  一个{
		颜色：#9db4ff；
	  }

	  前 {
		背景颜色：#282a36；
		边框颜色：#6272a4；
	  }
	}
	</style>

	<!-- 添加 FontAwesome 库 -->
	<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css'>
  </head>
  `；

	// 用换行符连接输出，包装在 <html> 和 <body> 内
	返回`
  <html>
  ${htmlHead}
  <主体>
  <pre style='background-color: transparent; border: none;'>${header} </pre>
  <pre>${输出}</pre>
  </body>
  <脚本>
	函数copyToClipboard（文本）{
	  navigator.clipboard.writeText（文本）
		.then(() => {
		  alert("已复制到剪贴板");
		})
		.catch((错误) => {
		  console.error("无法复制到剪贴板:", err);
		});
	}
  </script>
  `;
}

const เซ็ตพอร์ตHttp = new Set([80, 8080, 8880, 2052, 2086, 2095, 2082]);
const เซ็ตพอร์ตHttps = new Set([443, 8443, 2053, 2096, 2087, 2083]);

函数สร้างวเลสSub(ไอดีผู้ใช้_เส้นทาง,ชื่อโฮสต์){
	const อาร์เรย์ไอดีผู้ใช้ = ไอดีผู้ใช้_เส้นทาง.includes(',') ? ไอดีผู้ใช้_เส้นทาง.split(',') : [ไอดีผู้ใช้_เส้นทาง];
	const ส่วนUrlทั่วไปHttp = `?加密=无&安全=无&fp=随机&类型=ws&主机=${ชื่อโฮสต์}&path=%2F%3Fed%3D2048#`;
	const ส่วนUrlทั่วไปHttps = `?加密=无&安全=tls&sni=${ชื่อโฮสต์}&fp=随机&type=ws&host=${ชื่อโฮสต์}&path=%2F%3Fed%3D2048#`;

	const ผลลัพธ์ = อาร์เรย์ไอดีผู้ใช้.flatMap((ไอดีผู้ใช้) => {
		const การกำหนดค่าHttp = Array.from(เซ็ตพอร์ตHttp).flatMap((พอร์ต) => {
			if (!ชื่อโฮสต์.includes('pages.dev')) {
				const ส่วนUrl = `${ชื่อโฮสต์}-HTTP-${พอร์ต}`;
				const วเลสหลักHttp = atob(pt) + '://' + ไอดีผู้ใช้ + atob(at) + ชื่อโฮสต์ + ':' + พอร์ต + ส่วนUrlทั่วไปHttp + ส่วนUrl;
				return พร็อกซีไอพีs.flatMap((พร็อกซีไอพี) => {
					const วเลสรองHttp = atob(pt) + '://' + ไอดีผู้ใช้ + atob(at) + พร็อกซีไอพี + ':' + พอร์ต + ส่วนUrlทั่วไปHttp + ส่วนUrl + '-' + พร็อกซีไอพี + '-' + atob(ed);
					返回[วเลสหลักHttp,วเลสรองHttp];
				});
			}
			返回 [];
		});

		const การกำหนดค่าHttps = Array.from(เซ็ตพอร์ตHttps).flatMap((พอร์ต) => {
			const ส่วนUrl = `${ชื่อโฮสต์}-HTTPS-${พอร์ต}`;
			const วเลสหลักHttps = atob(pt) + '://' + ไอดีผู้ใช้ + atob(at) + ชื่อโฮสต์ + ':' + พอร์ต + ส่วนUrlทั่วไปHttps + ส่วนUrl;
			return พร็อกซีไอพีs.flatMap((พร็อกซีไอพี) => {
				const วเลสรองHttps = atob(pt) + '://' + ไอดีผู้ใช้ + atob(at) + พร็อกซีไอพี + ':' + พอร์ต + ส่วนUrlทั่วไปHttps + ส่วนUrl + '-' + พร็อกซีไอพี + '-' + atob(ed);
				返回[วเลสหลักHttps,วเลสรองHttps];
			});
		});

		返回 [...การกำหนดค่าHttp, ...การกำหนดค่าHttps];
	});

	return ผลลัพธ์.join('\n');
}

const cn_hostnames = [
	'weibo.com', // 微博 - 一个流行的社交媒体平台
	'www.baidu.com', // 百度 - 中国最大的搜索引擎
	'www.qq.com', // QQ - 广泛使用的即时通讯平台
	'www.taobao.com', // 淘宝 - 阿里巴巴集团旗下的电子商务网站
	'www.jd.com', // 京东 - 中国最大的在线零售商之一
	'www.sina.com.cn', // 新浪 - 一家中国在线媒体公司
	'www.sohu.com', // 搜狐 - 中国互联网服务提供商
	'www.tmall.com', // 天猫 - 阿里巴巴集团旗下的在线零售平台
	'www.163.com', // 网易邮箱 - 中国主要电子邮件提供商之一
	'www.zhihu.com', // 知乎 - 一个流行的问答网站
	'www.youku.com', // 优酷 - 中国视频分享平台
	'www.xinhuanet.com', // 新华社 - 中国官方通讯社
	'www.douban.com', // 豆瓣 - 中国社交网络服务
	'www.meituan.com', // 美团 - 一家提供本地服务的中国团购网站
	'www.toutiao.com', // 今日头条 - 新闻资讯内容平台
	'www.ifeng.com', // 凤凰网 - 中国知名新闻网站
	'www.autohome.com.cn', // 汽车之家 - 中国领先的汽车在线平台
	'www.360.cn', // 360 - 一家中国互联网安全公司
	'www.douyin.com', // 抖音 - 中国短视频平台
	'www.kuaidi100.com', // 快的100 - 中国快递追踪服务
	'www.wechat.com', // 微信 - 一款流行的消息和社交媒体应用程序
	'www.csdn.net', // CSDN - 中国技术社区网站
	'www.imgo.tv', // ImgoTV - 中国直播平台
	'www.aliyun.com', // 阿里云 - 一家中国云计算公司
	'www.eyny.com', // Eyny - 中文多媒体资源共享网站
	'www.mgtv.com', // MGTV - 一个中文在线视频平台
	'www.xunlei.com', // 迅雷 - 一款中文下载管理器和种子客户端
	'www.hao123.com', // Hao123 - 中文网站目录服务
	'www.bilibili.com', // Bilibili - 中国视频分享和流媒体平台
	'www.youth.cn', // Youth.cn - 中国青年报新闻门户网站
	'www.hupu.com', // 虎扑 - 中国体育社区和论坛
	'www.youzu.com', // 游族网络 - 中国游戏开发商和发行商
	'www.panda.tv', // 熊猫TV - 中国直播平台
	'www.tudou.com', // 土豆 - 中国视频分享网站
	'www.zol.com.cn', // ZOL - 中国电子产品和小工具网站
	'www.toutiao.io', // 今日头条 - 新闻资讯应用
	'www.tiktok.com', // TikTok - 一款中国短视频应用
	'www.netease.com', // 网易 - 一家中国互联网科技公司
	'www.cnki.net', // CNKI - 中国国家知识基础设施，信息聚合器
	'www.zhibo8.cc', // 智博8 - 一个提供体育直播的网站
	'www.zhangzishi.cc', // 张子石 - 中国公共知识分子张子石的个人网站
	'www.xueqiu.com', // 雪球 - 一个面向投资者和交易者的中国在线社交平台
	'www.qqgongyi.com', // QQ公益 - 腾讯公益慈善基金会平台
	'www.ximalaya.com', // 喜马拉雅 - 中文在线音频平台
	'www.dianping.com', // 大众点评 - 一个用于查找和评论本地商家的中国在线平台
	'www.suning.com', // 苏宁 - 中国领先的在线零售商
	'www.zhaopin.com', // 智联招聘 - 中国求职招聘平台
	'www.jianshu.com', // 简书 - 中文在线写作平台
	'www.mafengwo.cn', // 蚂蜂窝 - 中国旅游信息分享平台
	'www.51cto.com', // 51CTO - 中国IT技术社区网站
	'www.qidian.com', // 起点中文网 - 一个中文网络小说平台
	'www.ctrip.com', // 携程 - 中国旅行服务提供商
	'www.pconline.com.cn', // PConline - 中国科技新闻和评论网站
	'www.cnzz.com', // CNZZ - 中国网络分析服务提供商
	'www.telegraph.co.uk', // 每日电讯报 - 英国报纸网站	
	'www.ynet.com' // Ynet - 中国新闻门户网站
	'www.ted.com', // TED - 一个值得传播思想的平台
	'www.renren.com', // 人人网 - 中国社交网络服务
	'www.pptv.com', // PPTV - 中国在线视频流媒体平台
	'www.liepin.com', // 猎聘 - 中国在线招聘网站
	'www.881903.com', // 881903 - 香港电台网站
	'www.aipai.com', // 爱拍 - 中国在线视频分享平台
	'www.ttpaihang.com', // ttpaihang - 中国明星人气排行榜网站
	'www.quyaoya.com', // 曲瑶雅 - 中国在线票务平台
	'www.91.com', // 91.com - 中国软件下载网站
	'www.dianyou.cn', // 电游 - 中国游戏资讯网站
	'www.tmtpost.com', // 钛媒体 - 中国科技媒体平台
	'www.douban.com', // 豆瓣 - 中国社交网络服务
	'www.guancha.cn', // 观察者网 - 中国新闻评论网站
	'www.so.com', // So.com - 中文搜索引擎
	'www.58.com', // 58.com - 中国分类广告网站
	'www.cnblogs.com', // Cnblogs - 中文科技博客社区
	'www.cntv.cn', // CCTV - 中国中央电视台官方网站
	'www.secoo.com', // 寺库 - 中国奢侈品电商平台
]；
