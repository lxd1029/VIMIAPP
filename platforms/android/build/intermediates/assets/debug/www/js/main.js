/* 设置窗口高度 */
var $video = $("#_vl_video_component video").height();
var $chatinfo = $(".chatinfo").height();
var $ChatThread = $("#ChatThread");
var $form = $(".form").height();
/* 设置高度结束 */

/* MD5 */
/**
 * jQuery MD5 hash algorithm function
 * 
 * 	<code>
 * 		Calculate the md5 hash of a String 
 * 		String $.md5 ( String str )
 * 	</code>
 * 
 * Calculates the MD5 hash of str using the » RSA Data Security, Inc. MD5 Message-Digest Algorithm, and returns that hash. 
 * MD5 (Message-Digest algorithm 5) is a widely-used cryptographic hash function with a 128-bit hash value. MD5 has been employed in a wide variety of security applications, and is also commonly used to check the integrity of data. The generated hash is also non-reversable. Data cannot be retrieved from the message digest, the digest uniquely identifies the data.
 * MD5 was developed by Professor Ronald L. Rivest in 1994. Its 128 bit (16 byte) message digest makes it a faster implementation than SHA-1.
 * This script is used to process a variable length message into a fixed-length output of 128 bits using the MD5 algorithm. It is fully compatible with UTF-8 encoding. It is very useful when u want to transfer encrypted passwords over the internet. If you plan using UTF-8 encoding in your project don't forget to set the page encoding to UTF-8 (Content-Type meta tag). 
 * This function orginally get from the WebToolkit and rewrite for using as the jQuery plugin.
 * 
 * Example
 * 	Code
 * 		<code>
 * 			$.md5("I'm Persian."); 
 * 		</code>
 * 	Result
 * 		<code>
 * 			"b8c901d0f02223f9761016cfff9d68df"
 * 		</code>
 * 
 * @alias Muhammad Hussein Fattahizadeh < muhammad [AT] semnanweb [DOT] com >
 * @link http://www.semnanweb.com/jquery-plugin/md5.html
 * @see http://www.webtoolkit.info/
 * @license http://www.gnu.org/licenses/gpl.html [GNU General Public License]
 * @param {jQuery} {md5:function(string))
 * @return string
 */
(function($) {
	var rotateLeft = function(lValue, iShiftBits) {
		return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
	}
	var addUnsigned = function(lX, lY) {
		var lX4, lY4, lX8, lY8, lResult;
		lX8 = (lX & 0x80000000);
		lY8 = (lY & 0x80000000);
		lX4 = (lX & 0x40000000);
		lY4 = (lY & 0x40000000);
		lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
		if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
		if (lX4 | lY4) {
			if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
			else return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
		} else {
			return (lResult ^ lX8 ^ lY8);
		}
	}
	var F = function(x, y, z) {
		return (x & y) | ((~x) & z);
	}
	var G = function(x, y, z) {
		return (x & z) | (y & (~z));
	}
	var H = function(x, y, z) {
		return (x ^ y ^ z);
	}
	var I = function(x, y, z) {
		return (y ^ (x | (~z)));
	}
	var FF = function(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	};
	var GG = function(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	};
	var HH = function(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	};
	var II = function(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	};
	var convertToWordArray = function(string) {
		var lWordCount;
		var lMessageLength = string.length;
		var lNumberOfWordsTempOne = lMessageLength + 8;
		var lNumberOfWordsTempTwo = (lNumberOfWordsTempOne - (lNumberOfWordsTempOne % 64)) / 64;
		var lNumberOfWords = (lNumberOfWordsTempTwo + 1) * 16;
		var lWordArray = Array(lNumberOfWords - 1);
		var lBytePosition = 0;
		var lByteCount = 0;
		while (lByteCount < lMessageLength) {
			lWordCount = (lByteCount - (lByteCount % 4)) / 4;
			lBytePosition = (lByteCount % 4) * 8;
			lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
			lByteCount++;
		}
		lWordCount = (lByteCount - (lByteCount % 4)) / 4;
		lBytePosition = (lByteCount % 4) * 8;
		lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
		lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
		lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
		return lWordArray;
	};
	var wordToHex = function(lValue) {
		var WordToHexValue = "",
			WordToHexValueTemp = "",
			lByte, lCount;
		for (lCount = 0; lCount <= 3; lCount++) {
			lByte = (lValue >>> (lCount * 8)) & 255;
			WordToHexValueTemp = "0" + lByte.toString(16);
			WordToHexValue = WordToHexValue + WordToHexValueTemp.substr(WordToHexValueTemp.length - 2, 2);
		}
		return WordToHexValue;
	};
	var uTF8Encode = function(string) {
		string = string.replace(/\x0d\x0a/g, "\x0a");
		var output = "";
		for (var n = 0; n < string.length; n++) {
			var c = string.charCodeAt(n);
			if (c < 128) {
				output += String.fromCharCode(c);
			} else if ((c > 127) && (c < 2048)) {
				output += String.fromCharCode((c >> 6) | 192);
				output += String.fromCharCode((c & 63) | 128);
			} else {
				output += String.fromCharCode((c >> 12) | 224);
				output += String.fromCharCode(((c >> 6) & 63) | 128);
				output += String.fromCharCode((c & 63) | 128);
			}
		}
		return output;
	};
	$.extend({
		md5: function(string) {
			var x = Array();
			var k, AA, BB, CC, DD, a, b, c, d;
			var S11 = 7,
				S12 = 12,
				S13 = 17,
				S14 = 22;
			var S21 = 5,
				S22 = 9,
				S23 = 14,
				S24 = 20;
			var S31 = 4,
				S32 = 11,
				S33 = 16,
				S34 = 23;
			var S41 = 6,
				S42 = 10,
				S43 = 15,
				S44 = 21;
			string = uTF8Encode(string);
			x = convertToWordArray(string);
			a = 0x67452301;
			b = 0xEFCDAB89;
			c = 0x98BADCFE;
			d = 0x10325476;
			for (k = 0; k < x.length; k += 16) {
				AA = a;
				BB = b;
				CC = c;
				DD = d;
				a = FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
				d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
				c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
				b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
				a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
				d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
				c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
				b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
				a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
				d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
				c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
				b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
				a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
				d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
				c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
				b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
				a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
				d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
				c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
				b = GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
				a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
				d = GG(d, a, b, c, x[k + 10], S22, 0x2441453);
				c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
				b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
				a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
				d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
				c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
				b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
				a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
				d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
				c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
				b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
				a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
				d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
				c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
				b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
				a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
				d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
				c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
				b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
				a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
				d = HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
				c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
				b = HH(b, c, d, a, x[k + 6], S34, 0x4881D05);
				a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
				d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
				c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
				b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
				a = II(a, b, c, d, x[k + 0], S41, 0xF4292244);
				d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
				c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
				b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
				a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
				d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
				c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
				b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
				a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
				d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
				c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
				b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
				a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
				d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
				c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
				b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
				a = addUnsigned(a, AA);
				b = addUnsigned(b, BB);
				c = addUnsigned(c, CC);
				d = addUnsigned(d, DD);
			}
			var tempValue = wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d);
			return tempValue.toLowerCase();
		}
	});
})(jQuery);
/* MD5结束 */
/* 哈希表 */
var hash = new HashTable();

function HashTable() {
	var size = 0;
	var entry = new Object();
	this.add = function(key, value) {
		if (!this.containsKey(key)) {
			size++;
		}
		entry[key] = value;
	}
	this.getValue = function(key) {
		return this.containsKey(key) ? entry[key] : null;
	}
	this.remove = function(key) {
		if (this.containsKey(key) && (delete entry[key])) {
			size--;
		}
	}
	this.containsKey = function(key) {
		return (key in entry);
	}
	this.containsValue = function(value) {
		for (var prop in entry) {
			if (entry[prop] == value) {
				return true;
			}
		}
		return false;
	}
	this.getValues = function() {
		var values = new Array();
		for (var prop in entry) {
			values.push(entry[prop]);
		}
		return values;
	}
	this.getKeys = function() {
		var keys = new Array();
		for (var prop in entry) {
			keys.push(prop);
		}
		return keys;
	}
	this.getSize = function() {
		return size;
	}
	this.clear = function() {
		size = 0;
		entry = new Object();
	}
}
/* 哈希表 */
/* 时间获取 */
function GetSendTime() {
	var Datetime = new Date();
	hour = Datetime.getHours();
	minute = Datetime.getMinutes();
	return hour + ':' + minute;
}
/* 时间获取 */
/* ASCII转换Unicode */
var hexChars = "0123456789ABCDEF";

function toHex(n) {
	var nH = (n >> 4) & 0x0f;
	var nL = n & 0x0f;
	return hexChars.charAt(nH) + hexChars.charAt(nL);
}

function ascii2native(strAscii) {
	var output = "";
	var posFrom = 0;
	var posTo = strAscii.indexOf("\\u", posFrom);
	while (posTo >= 0) {
		output += strAscii.substring(posFrom, posTo);
		output += toChar(strAscii.substr(posTo, 6));
		posFrom = posTo + 6;
		posTo = strAscii.indexOf("\\u", posFrom);
	}
	output += strAscii.substr(posFrom);
	return output;
};

function toChar(str) {
	if (str.substr(0, 2) != "\\u") return str;

	var code = 0;
	for (var i = 2; i < str.length; i++) {
		var cc = str.charCodeAt(i);
		if (cc >= 0x30 && cc <= 0x39)
			cc = cc - 0x30;
		else if (cc >= 0x41 && cc <= 0x5A)
			cc = cc - 0x41 + 10;
		else if (cc >= 0x61 && cc <= 0x7A)
			cc = cc - 0x61 + 10;

		code <<= 4;
		code += cc;
	}

	if (code < 0xff) return str;

	return String.fromCharCode(code);
}
/*ASCII转换Unicode结束*/
/* UserID生成 */
function randomString() {　　
	len = 9;　　
	var $chars = 'ABCDEFGHJKLMNOPQRSTUVWXYZabcdefhijklmnopqrstuvwxyz0123456789';
	var maxPos = $chars.length;　　
	var pwd = '';　　
	for (i = 0; i < len; i++) {　　　　
		pwd += $chars.charAt(Math.floor(Math.random() * maxPos));　　
	}　　
	return pwd;
};

/* UserID生成结束 */
/* 发送内容 */
function getEmit() {
	socket.emit("Message", getEmitObj());
	$("#ChatConSub").siblings().val("");
};
/* 发送内容 */
    var socket = io.connect('http://115.28.241.178:8546');
    socket.on("connect", function() {
        var o = {};
        o.Type = "UL_Add";
        o.RoomID = 7000;
        o.Data = [];
        o.Data.length = 0;
        o.Data.push(GetSimpleUInfo());
        //发送身份信息

        socket.emit("Message", o);
    });
    socket.on('Message', function(data) {
        // console.log(data);
        var data1 = JSON.parse(data);
        if (!hash.containsKey(data1.MD5)) {
            hash.add(data1.MD5, data1.Msg);
            var chat = hash.getValue(data1.MD5);
            /*  获取聊天内容  */
            if (!hash.containsKey(data1.Time)) {
                hash.add(data1.Time, data1.Time);
                var chattime = hash.getValue(data1.Time);
            }
            var chattime = hash.getValue(data1.Time);

            if (!hash.containsKey(data1.PostUID)) {
                hash.add(data1.PostUID, data1.PostUID);
                var chatname = hash.getValue(data1.PostUID);
            }
            var chatname = hash.getValue(data1.PostUID);
            /* 聊天设置 */
            if (chat == undefined) {
                return false;
            }
            var chatcon = ascii2native(chat);
            console.log(typeof chatcon);
            var para = document.createElement("li");
            var b = document.createElement("b");
            var span = document.createElement("span");
            var node = document.createTextNode(chatcon);
            var nodetime = document.createTextNode(chattime);
            var nodename = document.createTextNode(chatname);
            para.setAttribute("class", "chat-else");
            para.appendChild(node);
            span.appendChild(nodetime);
            b.appendChild(nodename);

            var element = document.getElementById("ChatThread");
            element.appendChild(para);
            var elementlast = element.lastChild;
            elementlast.insertBefore(b, elementlast.childNodes[0]);
            elementlast.insertBefore(span, elementlast.childNodes[0]);
            element.scrollTop = element.scrollHeight;
            /* 聊天设置结束 */
        }
        // document.write(data1.Msg)
    });
    function GetSimpleUInfo() {
        var e = {};
        e.Type = 'Msg_Public'; //公共
        e.IsLogin = false;
        e.UserID = randomString();
        e.PostUID = randomString();
        e.UserNickName = "我是游客";
        e.RoomID = 7000;
        e.LevelID = 0;
        e.FacePic = "";
        e.Time = GetSendTime();
        e.Msg = $(".form :text").val().split("@").join("");
        e.MD5 = $.md5($(".form :text").val()); //消息的MD5标识,用以管理员审核
        e.IsManager = false;
        e.Power = 0; //观众,管理,房间创建者的权重   
        e.SeatStyle = ""; //座驾样式
        e.SeatName = ""; //座驾名称
        e.RoleCssStyle = ""; //角色样式
        e.RoleName = ""; //角色名称
        e.RoleID = 0; //角色ID
        e.RoleWeight = 0; //角色权重
        e.RoomRoleStyle = "RoomUser3"; //房间角色样式
        e.RoomRoleTitle = ""; //房间角色说明
        e.IsZber = true;
        e.EnterTime = new Date();
        e.iPhone = false;
        e.iPad = true;
        e.mobile = true;
        return e;
    };
    function getEmitObj(){
        var o = {};
        o.Type = 'Msg_Public';
        o.ReceiveRID = "7000";
        o.PostUID = randomString();
        o.PostUName = o.PostUID;
        o.PostPower = 0;
        o.ReceiveUID = 0;
        o.ReceiveUName = "";
        o.ReceivePower = 0;

        o.RoleStyle = "";
        o.ZberStyle = 'RoomBo';
        o.RoomRoleStyle = "RoomUser3";
        o.RoomRoleTitle = "";

        o.Receive_RoleStyle = "";
        o.Receive_ZberStyle = "";
        o.Receive_RoomRoleStyle = "";
        o.Receive_RoomRoleTitle = "";

        o.PostRoleTitle = "游客";
        o.ReceiveRoleTitle = "";

        o.Time = GetSendTime();
        o.Msg = $(".form :text").val().split("@").join("");;
        o.MD5 = $.md5($(".form :text").val());; //消息的MD5标识,用以管理员审核
        o.Checked = true;
        return o;
    }