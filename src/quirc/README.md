# quirc

Camera backup scanning uses the C decoder from Daniel Beer's quirc at commit `f2e4271ae43a15d9263704e07bc86cba5697d74d`. Each source file includes the upstream license. The wallet clears the corrected byte stream before `quirc_decode()` returns and wipes its frame, bitmap and payload buffers after processing. [Upstream source](https://github.com/dlbeer/quirc/tree/f2e4271ae43a15d9263704e07bc86cba5697d74d/lib)
