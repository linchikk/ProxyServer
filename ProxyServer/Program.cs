using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace ProxyServer
{
    class Program
    {
        // Флаги и настройки сервера
        public static bool IsRunning = true;
        public const int BUFFER = 8192;
        public static IPAddress ListenIp = IPAddress.Parse("127.0.0.2"); // Слушаем на 127.0.0.2
        public const int Port = 8888;

        static void Main(string[] args)
        {
            TcpListener listener = new TcpListener(ListenIp, Port);
            listener.Start();
            Console.WriteLine($"Прокси-сервер запущен на порту {Port}");

            // Основной цикл ожидания входящих подключений
            while (IsRunning)
            {
                try
                {
                    Socket clientSocket = listener.AcceptSocket();
                    IPEndPoint remoteEP = clientSocket.RemoteEndPoint as IPEndPoint;
                    Thread thread = new Thread(() => HandleClient(clientSocket));
                    thread.IsBackground = true;
                    thread.Start();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка при подключении клиента: {ex.Message}");
                }
            }
        }

        static void HandleClient(Socket client)
        {
            try
            {
                using (NetworkStream clientStream = new NetworkStream(client))
                {
                    // Получаем HTTP-запрос от клиента
                    byte[] httpRequest = Receive(clientStream);
                    if (httpRequest.Length == 0)
                    {
                        client.Close();
                        return;
                    }

                    // Преобразуем запрос в строку для разбора
                    string fullRequest = Encoding.UTF8.GetString(httpRequest);

                    // Извлекаем хост и удалённую конечную точку
                    string host;
                    IPEndPoint remoteEndPoint = GetRemoteEndpoint(fullRequest, out host);


                    // Если запрос содержит абсолютный URL (например, "GET http://..."), преобразуем в относительный
                    if (fullRequest.StartsWith("GET http", StringComparison.OrdinalIgnoreCase) ||
                        fullRequest.StartsWith("POST http", StringComparison.OrdinalIgnoreCase))
                    {
                        fullRequest = GetRelativePath(fullRequest);
                    }

                    byte[] fixedRequestBytes = Encoding.UTF8.GetBytes(fullRequest);

                    // Передаём запрос на удалённый сервер и стримим ответ клиенту (с обработкой медиа-потоков)
                    Response(clientStream, fixedRequestBytes, remoteEndPoint, host);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при обработке клиента: {ex.Message}");
            }
            finally
            {
                client.Close();
            }
        }

        /// <summary>
        /// Чтение входящего потока до отсутствия доступных данных.
        /// </summary>
        static byte[] Receive(NetworkStream stream)
        {
            byte[] bufData = new byte[BUFFER];
            List<byte> data = new List<byte>();
            int bytesRead = 0;
            try
            {
                // Читаем данные, пока они доступны
                do
                {
                    bytesRead = stream.Read(bufData, 0, bufData.Length);
                    if (bytesRead > 0)
                    {
                        data.AddRange(bufData.Take(bytesRead));
                    }
                } while (stream.DataAvailable);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при чтении из потока: {ex.Message}");
            }
            return data.ToArray();
        }

        /// <summary>
        /// Преобразует абсолютный URL в относительный путь.
        /// </summary>
        static string GetRelativePath(string request)
        {
            Regex regex = new Regex(@"http:\/\/[a-z0-9а-я\.\:]*", RegexOptions.IgnoreCase);
            return regex.Replace(request, "");
        }

        /// <summary>
        /// Извлекает из HTTP-запроса заголовок Host и определяет удалённую конечную точку.
        /// </summary>
        static IPEndPoint GetRemoteEndpoint(string request, out string host)
        {
            Regex regex = new Regex(@"Host:\s*(?<host>[^:\r\n]+)(:(?<port>\d+))?", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            Match match = regex.Match(request);
            host = match.Groups["host"].Value;
            int port = 80;
            if (!string.IsNullOrEmpty(match.Groups["port"].Value))
            {
                int.TryParse(match.Groups["port"].Value, out port);
            }
            IPAddress[] addresses = Dns.GetHostAddresses(host);
            IPAddress ipAddress = addresses.Length > 0 ? addresses[0] : IPAddress.Loopback;
            return new IPEndPoint(ipAddress, port);
        }

        /// <summary>
        /// Соединяется с удалённым сервером по указанной конечной точке, отправляет ему запрос и стримит его ответ клиенту.
        /// Реализация организована так, чтобы корректно работать с потоковыми медиа (например, аудио).
        /// </summary>
        static void Response(NetworkStream clientStream, byte[] requestBytes, IPEndPoint remoteEP, string host)
        {
            try
            {
                using (Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    serverSocket.Connect(remoteEP);
                    using (NetworkStream serverStream = new NetworkStream(serverSocket))
                    {
                        // Отправляем исправленный запрос на удалённый сервер
                        serverStream.Write(requestBytes, 0, requestBytes.Length);
                        serverStream.Flush();

                        byte[] buffer = new byte[BUFFER];
                        int bytesRead;
                        bool headerParsed = false;
                        List<byte> headerAccumulator = new List<byte>();
                        string statusLine = "";
                        bool logEveryChunk = false;

                        // Читаем ответ от удалённого сервера блоками
                        while ((bytesRead = serverStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            // Передаём полученные данные клиенту
                            clientStream.Write(buffer, 0, bytesRead);
                            clientStream.Flush();

                            // Обработка заголовка (накапливаем его, чтобы проанализировать Content-Type, status и т.п.)
                            if (!headerParsed)
                            {
                                for (int i = 0; i < bytesRead; i++)
                                {
                                    headerAccumulator.Add(buffer[i]);
                                }
                                string headerText = Encoding.UTF8.GetString(headerAccumulator.ToArray());
                                int headerEnd = headerText.IndexOf("\r\n\r\n");
                                if (headerEnd != -1)
                                {
                                    string headerSection = headerText.Substring(0, headerEnd);
                                    string[] headerLines = headerSection.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                                    if (headerLines.Length > 0)
                                    {
                                        statusLine = headerLines[0];
                                    }
                                    headerParsed = true;

                                    // Если контент имеет тип аудио, ведём лог при получении каждого чанка
                                    if (headerText.ToLower().Contains("content-type:") &&
                                        headerText.ToLower().Contains("audio"))
                                    {
                                        logEveryChunk = true;
                                    }
                                    Console.WriteLine($"{DateTime.Now} {host} {statusLine}");
                                }
                                else
                                {
                                    Console.WriteLine($"{DateTime.Now} {host} — получаю заголовок, накоплено {headerAccumulator.Count} байт");
                                }
                            }
                            else
                            {
                                if (logEveryChunk)
                                {
                                    Console.WriteLine($"{DateTime.Now} {host} {statusLine}");
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
            }
        }
    }
}
