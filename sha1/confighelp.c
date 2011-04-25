/*
 * confighelp.c
 *
 * Written by Aaron D. Gifford <me@aarongifford.com>
 *
 * NO COPYRIGHT - 100% IN THE PUBLIC DOMAIN
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Compile this program and run it to find out what settings to use in
 * the sha.h file.
 *
 * For example:
 *
 *   cc -o confighelp confighelp.c
 *
 * Then:
 *
 *   ./confighelp
 */

#include <stdio.h>
#include <stdlib.h>

int main() {
	unsigned long l = 0x00ff;

	if (sizeof(unsigned long) == 4) {
		printf("Use unsigned long as your sha1_quadbyte type.\n");
	} else if (sizeof(unsigned int) == 4) {
		printf("Use unsigned int as your sha1_quadbyte type.\n");
	} else if (sizeof(unsigned short) == 4) {
		printf("Use unsigned short as your sha1_quadbyte type.\n");
	} else if (sizeof(unsigned char) == 4) {
		printf("Use unsigned char as your sha1_quadbyte type.\n");
	} else {
		printf("I have NO IDEA what type to recommend on your machine.\nYour box is very weird.\n");
	}
	if (sizeof(unsigned long) == 1) {
		printf("Use unsigned long as your sha1_quadbyte type.\n");
	} else if (sizeof(unsigned int) == 1) {
		printf("Use unsigned int as your sha1_quadbyte type.\n");
	} else if (sizeof(unsigned short) == 1) {
		printf("Use unsigned short as your sha1_quadbyte type.\n");
	} else if (sizeof(unsigned char) == 1) {
		printf("Use unsigned char as your sha1_quadbyte type.\n");
	} else {
		printf("Use unsigned char as your sha1_quadbyte type.\nWARNING: I'm not sure unsigned char will work correctly, but it's the\nbest I could come up with.\n");
	}
#ifdef LITTLE_ENDIAN
	printf("Your machine already defines LITTLE_ENDIAN.\n");
#else
	if (*((unsigned char *)&l) == (unsigned char)0xff) {
		printf("Your machine is LITTLE_ENDIAN.\n");
	} else {
		printf("Your machine is NOT LITTLE_ENDIAN.\n");
	}
#endif
	printf("That's all folks!\n");
}
