#![no_std]
//! This example creates a CoAP server and provides some command line interaction.
//!
//! It resembles the gcoap RIOT example, but does not contain the shell (and thus CoAP client)
//! part.

use riot_wrappers::{
    gcoap,
    riot_main,
    thread,
    stdio::println,
    self,
};


use core::fmt::Write;
use riot_wrappers::cstr::cstr;
use coap_handler_implementations::SimpleRendered;

// Wrap main into a C function named `int main(void)` function that is invoked as the main thread
// function by RIOT.
riot_main!(main);

fn main() {

    use riot_wrappers::shell::CommandList;
    let mut commands = riot_shell_commands::all();
    commands.run_forever_providing_buf();

    println!("Preparing CoAP server");

    // FIXME given we're using this in a "One read-modify-writes, others read only" pattern, there
    // might be a better abstraction
    let req_count = core::cell::Cell::new(0);

    let mut riot_board_handler = riot_wrappers::coap_handler::GcoapHandler(SimpleRendered(RiotBoardHandler()));
    let mut stats_handler = riot_wrappers::coap_handler::GcoapHandler(SimpleRendered(StatsHandler(&req_count)));
    let mut poem_handler = riot_wrappers::coap_handler::GcoapHandler(SimpleRendered(PoemHandler()));

    // Rather than having a single handler, dispatch could be handled by a coap_handler (but then
    // it's not exposed that nicely via .well-known/ocre), or by something better than
    // SingleHandlerListener that builds a non-single listener.
    let mut boardlistener = gcoap::SingleHandlerListener::new(cstr!("/riot/board"), riot_sys::COAP_GET, &mut riot_board_handler);
    let mut statslistener = gcoap::SingleHandlerListener::new(cstr!("/cli/stats"), riot_sys::COAP_GET | riot_sys::COAP_PUT, &mut stats_handler);

    let mut boardlistener = gcoap::SingleHandlerListener::new(cstr!("/poem"), riot_sys::COAP_GET, &mut poem_handler);

    gcoap::scope(|greg| {
        greg.register(&mut boardlistener);
        greg.register(&mut statslistener);

        use embedded_hal::blocking::delay::DelayMs;
        use riot_wrappers::ztimer;
        println!("Waiting for server to be ready");
        ztimer::Clock::msec().delay_ms(3000);
        println!("Sending request via different (embedded-nal) CoAP (pseudo)stack");

        // Use a completely different CoAP implementation to query loopback...
        let server_coap = embedded_nal::SocketAddrV6::new(embedded_nal::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 5683, 0, 0);
        use embedded_nal::UdpClientStack;
        let mut stack: riot_wrappers::socket_embedded_nal::Stack<1> = riot_wrappers::socket_embedded_nal::Stack::new();
        stack.run(|mut stack| {
            let mut sock = stack.socket().unwrap();
            stack.connect(&mut sock, server_coap.into()).unwrap();

            stack.send(&mut sock, b"\x50\x01\0\0\xbb.well-known\x04core").unwrap();
            let mut response = [0; 1280];
            // FIXME: allow a few retries as it's now fully nonblocking
            let (read, source) = stack.receive(&mut sock, &mut response).unwrap();
            let response = &response[..read];
            println!("Got {:?} from {:?}", response, source);

            stack.close(sock).unwrap();

            // Cleanup does not work well yet
            loop { thread::sleep(); }
        });
        // Not that it'd actually execute, because run doesn't return
        loop { thread::sleep(); }
    })
}

struct RiotBoardHandler();
impl coap_handler_implementations::SimpleRenderable for RiotBoardHandler {
    fn render<W: core::fmt::Write>(&mut self, writer: &mut W) {
        writeln!(writer, "{}",
                 core::str::from_utf8(riot_sys::RIOT_BOARD)
                     .expect("Oddly named board crashed CoAP stack")
            ).unwrap();

        // Compared to the C example, there is no "message too small" error case as
        // SimpleRenderable would use block-wise transfer in such cases.
    }
}

// PUT is missing, would need a more manual implementation or an extension to SimpleRenderable that
// has some read-able version as well.
struct StatsHandler<'a>(&'a core::cell::Cell<u32>);
impl<'a> coap_handler_implementations::SimpleRenderable for StatsHandler<'a> {
    fn render<W: core::fmt::Write>(&mut self, writer: &mut W) {
        writeln!(writer, "{}", self.0.get()).unwrap();
    }
}

struct PoemHandler();
impl coap_handler_implementations::SimpleRenderable for PoemHandler {
    fn render<W: core::fmt::Write>(&mut self, writer: &mut W) {
        writeln!(writer, "Aurea prima sata est aetas, quae vindice nullo,
sponte sua, sine lege fidem rectumque colebat.
Poena metusque aberant nec verba minantia fixo
aere legebantur, nec supplex turba timebat
iudicis ora sui, sed erant sine vindice tuti.
Nondum caesa suis, peregrinum ut viseret orbem,
montibus in liquidas pinus descenderat undas,
nullaque mortales praeter sua litora norant.
Nondum praecipites cingebant oppida fossae,
non tuba directi, non aeris cornua flexi,
non galeae, non ensis erant: sine militis usu
mollia securae peragebant otia gentes.

Ipsa quoque inmunis rastroque intacta nec ullis
saucia vomeribus per se dabat omnia tellus,
contentique cibis nullo cogente creatis
arbuteos fetus montanaque fraga legebant
cornaque et in duris haerentia mora rubetis
et quae deciderant patula Iovis arbore glandes.

Ver erat aeternum, placidique tepentibus auris
mulcebant zephyri natos sine semine flores;
mox etiam fruges tellus inarata ferebat,
nec renovatus ager gravidis canebat aristis;
flumina iam lactis, iam flumina nectaris ibant,
flavaque de viridi stillabant ilice mella.

Postquam Saturno tenebrosa in Tartara misso
sub Iove mundus erat, subiit argentea proles,
auro deterior, fulvo pretiosior aere.

Iuppiter antiqui contraxit tempora veris
perque hiemes aestusque et inaequalis autumnos
et breve ver spatiis exegit quattuor annum.
").unwrap()
    }
}
