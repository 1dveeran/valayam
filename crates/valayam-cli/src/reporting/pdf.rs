use valayam_core::core::result::ScanResult;
use genpdf::{elements, Document, SimplePageDecorator};
use std::fs::File;

pub fn generate_pdf(results: &[ScanResult], output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Generate a basic PDF report for MVP
    let font_paths = [
        ("./fonts", "Roboto"),
        ("/usr/share/fonts/truetype/dejavu", "DejaVuSans"),
        ("C:\\Windows\\Fonts", "arial"), 
        ("/System/Library/Fonts", "Helvetica"), 
    ];

    let mut font_family = None;
    for (dir, name) in font_paths {
        if let Ok(ff) = genpdf::fonts::from_files(dir, name, None) {
            font_family = Some(ff);
            break;
        }
    }

    let font_family = match font_family {
        Some(f) => f,
        None => return Err("Could not find any standard fonts on this system. Please provide fonts in ./fonts or use --format json".into()),
    };
    let mut doc = Document::new(font_family);
    doc.set_title("Valayam Enterprise Scan Report");
    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(10);
    doc.set_page_decorator(decorator);

    doc.push(elements::Paragraph::new("Valayam Security Scan Report").aligned(genpdf::Alignment::Center));
    doc.push(elements::Break::new(1));

    for res in results {
        let p = elements::Paragraph::new(format!("Finding: {} ({})", res.template_name, res.template_id));
        doc.push(p);
        let p2 = elements::Paragraph::new(format!("Target: {}", res.target));
        doc.push(p2);
        doc.push(elements::Break::new(1));
    }

    let mut file = File::create(output_path)?;
    doc.render(&mut file)?;
    Ok(())
}
