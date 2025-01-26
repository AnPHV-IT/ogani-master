const generateNonce = (bytes) => {
    const randomBytes = CryptoJS.lib.WordArray.random(bytes || 32);
    return randomBytes.toString(CryptoJS.enc.Hex);
};

const generateRequestId = () => {
    return uuid.v4();
};

const getCookie = (name) => {
    let value = "; " + document.cookie;
    let parts = value.split("; " + name + "=");
    if (parts.length === 2) return parts.pop().split(";").shift();
}

class ChatService {
    constructor(_HASH_MESSAGE_SECRET_KEY, _PUBLIC_SIGNATURE_CLIENT_ID) {
        this.socket = null;
        this.messageCallbacks = new Set();
        this.connected = false;
        this.HASH_MESSAGE_SECRET_KEY = _HASH_MESSAGE_SECRET_KEY
        this.PUBLIC_SIGNATURE_CLIENT_ID = _PUBLIC_SIGNATURE_CLIENT_ID
    }

    connect(token) {
        this.socket = io("http://localhost:3001/chat", {
            auth: { authorization: token },
            withCredentials: true,
            transports: ["websocket"],
        });

        this.socket.on('connect', () => {
            console.log('Connected to chat server');
            this.connected = true;
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from chat server');
            this.connected = false;
        });

        this.socket.on('message', (data) => {
            try {
                const decryptedMessage = this.decrypt(data.message, this.HASH_MESSAGE_SECRET_KEY);
                this.messageCallbacks.forEach(callback => callback(decryptedMessage));
            } catch (error) {
                console.error('Error decrypting message:', error);
            }
        });
    }

    generateHmac (message) {
        const secretKey = this.HASH_MESSAGE_SECRET_KEY;
        if (!secretKey) throw new Error("The secretKey is not available")
        return CryptoJS.HmacSHA256(message, secretKey).toString(CryptoJS.enc.Hex);
    };

    sendMessage(event, message, methodWs = 'POST', query = null, token) {
        if (!this.connected) {
            console.error('Not connected to chat server');
            return;
        }

        const nonce = generateNonce();
        const requestId = generateRequestId();
        const timestamp = new Date().getTime();
        const userAgent = navigator.userAgent;

        const encryptedMessage = this.encrypt(JSON.stringify(message), this.HASH_MESSAGE_SECRET_KEY);

        const messageParam = `url:${event}|body:${encryptedMessage}|nonce:${nonce}|timestamp:${timestamp}|requestId:${requestId}|userAgent:${userAgent}`;
        const signature = this.generateHmac(messageParam);

        const payload = {
            message: encryptedMessage,
            headers: {
                "x-request-nonce": nonce,
                "x-timestamp": timestamp,
                "x-request-id": requestId,
                "x-client-id": this.PUBLIC_SIGNATURE_CLIENT_ID,
                "x-user-agent": userAgent,
                "x-signature": signature,
                "x-socket-url": event,
            },
            authorization: token,
            method: methodWs,
            query,
        };

        this.socket.emit(event, payload);
    }

    onMessage(callback) {
        this.messageCallbacks.add(callback);
    }

    encrypt(text, key) {
        if (!key) throw new Error("No key specified");

        const iv = CryptoJS.lib.WordArray.random(16);
        const encrypted = CryptoJS.AES.encrypt(text, CryptoJS.enc.Hex.parse(key), {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
        });

        return `${iv.toString(CryptoJS.enc.Base64)}:${encrypted.ciphertext.toString(CryptoJS.enc.Base64)}`;
    }

    decrypt(encryptedText, key) {
        if (!key) throw new Error("No key specified");

        const parts = encryptedText.split(":");
        if (parts.length !== 2) throw new Error("Invalid encrypted text format");

        const [ivBase64, encryptedDataBase64] = parts;
        const iv = CryptoJS.enc.Base64.parse(ivBase64);
        const encryptedData = CryptoJS.enc.Base64.parse(encryptedDataBase64);
        const keyParsed = CryptoJS.enc.Hex.parse(key);

        const cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: encryptedData,
        });

        try {
            const decrypted = CryptoJS.AES.decrypt(cipherParams, keyParsed, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
            });

            const result = decrypted.toString(CryptoJS.enc.Utf8);
            if (!result) throw new Error("Decryption failed");
            return result;
        } catch (error) {
            throw new Error("Decryption failed");
        }
    }
}
